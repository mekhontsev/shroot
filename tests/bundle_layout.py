"""Read-only checks shared by native installation and cross-built archives."""
import json
import os
from pathlib import Path
import re
import subprocess


HELPERS = {'image', 'run', 'supervisor', 'bootstrap', 'service'}
HOST_LIBRARY = re.compile(r'(lib(c|m|dl|pthread|rt|gcc_s)\.so(\.\d+)*|'
                          r'libc\.musl-aarch64\.so\.1|ld-linux-aarch64\.so\.1)')


def elf_details(path, readelf):
    return subprocess.check_output([readelf, '-W', '-h', '-l', '-S', '-d', str(path)],
                                   text=True, env=dict(os.environ, LC_ALL='C'), timeout=30)


def audit_elf(path, readelf, *, dynamic, system):
    details = elf_details(path, readelf)
    assert re.search(r'Class:\s+ELF64\b', details), path
    assert re.search(r'Machine:\s+AArch64\b', details), path
    assert re.search(r'Data:.*little endian', details), path
    assert '.debug_info' not in details and '.zdebug_info' not in details, path
    needed = re.findall(r'\(NEEDED\).*\[([^\]]+)\]', details)
    if dynamic:
        assert needed and all(HOST_LIBRARY.fullmatch(name) for name in needed), (path, needed)
    else:
        assert not needed, (path, needed)
    assert not re.search(r'\((RPATH|RUNPATH)\)', details), (path, 'embedded library search path')
    loads = re.findall(r'^\s*LOAD\s+.*\s+(0x[0-9a-fA-F]+)\s*$', details, re.MULTILINE)
    assert loads and all(int(alignment, 16) >= 16384 for alignment in loads), (path, loads)
    interpreter = re.findall(r'Requesting program interpreter:\s*([^\]]+)', details)
    if interpreter:
        expected = (['/system/bin/linker64'] if system == 'Android' else
                    ['/lib/ld-linux-aarch64.so.1', '/lib64/ld-linux-aarch64.so.1',
                     '/lib/ld-musl-aarch64.so.1'])
        assert dynamic and interpreter[0] in expected, (path, interpreter)
    return needed


def audit_bundle(prefix, readelf='readelf', *, production=False, system=None, version=None):
    prefix = Path(prefix).resolve()
    runtime = prefix / 'libexec/shroot'
    metadata = json.loads((runtime / 'runtime.json').read_text())
    assert metadata['format'] == 1 and metadata['minimumKernel'] == '5.15', metadata
    assert metadata['system'] in ('Android', 'Linux'), metadata
    assert metadata['architecture'].lower() in ('aarch64', 'arm64'), metadata
    assert isinstance(metadata['testHooks'], bool), metadata
    if production:
        assert not metadata['testHooks'], 'Test-enabled runtime is not a production artifact'
    if system:
        assert metadata['system'] == system, metadata
    if version:
        assert metadata['version'] == version, metadata
    assert set(metadata['helpers']) == HELPERS, metadata
    files = set(metadata['helpers'].values())
    assert len(files) == len(HELPERS), 'Helper roles must name distinct executables'
    assert {path.name for path in runtime.iterdir()} == files | {'runtime.json'}
    binaries = [(prefix / 'bin/shroot', False), (prefix / 'lib/libshroot.so', True)]
    for role, name in metadata['helpers'].items():
        path = runtime / name
        assert Path(name).name == name and path.is_file() and not path.is_symlink(), name
        binaries.append((path, role == 'image'))
    for path, dynamic in binaries:
        assert path.resolve().is_relative_to(prefix), path
        audit_elf(path, readelf, dynamic=dynamic, system=metadata['system'])
    for filename in ('include/shroot.h', 'lib/libshroot.a', 'lib/cmake/Shroot/ShrootConfig.cmake',
                     'share/doc/shroot/LICENSE'):
        assert (prefix / filename).is_file(), filename
    for name in ('curl', 'mbedtls', 'lwip', 'zlib', 'zstd', 'libarchive'):
        assert (prefix / 'share/doc/shroot/licenses' / (name + '.txt')).is_file(), name
    return metadata
