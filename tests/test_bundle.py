#!/usr/bin/env python3
"""Qualify the installed default bundle, including relocation and ELF dependencies."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('--cmake', default='cmake')
    parser.add_argument('--readelf', default='readelf')
    args = parser.parse_args()
    build = args.build.resolve()
    with tempfile.TemporaryDirectory(prefix='shroot-bundle-', dir=build) as temporary:
        prefix = Path(temporary) / 'installed'
        subprocess.run([args.cmake, '--install', str(build), '--prefix', str(prefix),
                        '--component', 'Shroot', '--strip'], check=True, timeout=60)
        relocated = prefix.with_name('relocated bundle')
        prefix.rename(relocated)
        runtime = relocated / 'libexec/shroot'
        metadata = json.loads((runtime / 'runtime.json').read_text())
        assert metadata['format'] == 1 and metadata['minimumKernel'] == '5.15'
        cli = relocated / 'bin/shroot'
        version = subprocess.check_output([str(cli), '--version'], text=True, timeout=10)
        assert metadata['version'] == version.strip()
        assert set(metadata['helpers']) == {'image', 'run', 'supervisor', 'bootstrap', 'service'}
        for role, name in metadata['helpers'].items():
            assert Path(name).name == name and os.access(runtime / name, os.X_OK)
            dynamic = subprocess.check_output([args.readelf, '-d', str(runtime / name)], text=True)
            needed = re.findall(r'\(NEEDED\).*\[([^\]]+)\]', dynamic)
            if role == 'image':
                assert needed, 'image worker must use the host resolver libc'
                assert all(re.fullmatch(r'(lib(c|m|dl|pthread|rt|gcc_s)\.so(\.\d+)*|'
                                        r'libc\.musl-aarch64\.so\.1|ld-linux-aarch64\.so\.1)', name)
                           for name in needed), needed
            else:
                assert not needed, (role, needed)
            sections = subprocess.check_output([args.readelf, '-S', str(runtime / name)], text=True)
            assert '.debug_info' not in sections, role
        assert (relocated / 'lib/libshroot.a').is_file()
        assert (relocated / 'lib/libshroot.so').is_file()
        for license in ('curl.txt', 'mbedtls.txt', 'lwip.txt'):
            assert (relocated / 'share/doc/shroot/licenses' / license).is_file(), license
        subprocess.run([sys.executable, str(Path(__file__).with_name('test_client_runtime.py')),
                        str(build), '--prefix', str(relocated)], check=True, timeout=180)
        print('PASS relocated installed bundle: static dependencies, stripped helpers, API and CLI execution')


if __name__ == '__main__':
    main()
