#!/usr/bin/env python3
"""Package verified userspace with fixtures from an existing native CMake build."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

SOURCE = Path(__file__).resolve().parent


def run(*arguments):
    subprocess.run(list(map(str, arguments)), check=True)


def copy_tree(source, target):
    if source.is_symlink():
        target.symlink_to(os.readlink(source))
    else:
        shutil.copytree(source, target, symlinks=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('prepared', type=Path)
    parser.add_argument('--native-build', required=True, type=Path)
    parser.add_argument('--graphics', action='store_true', help='Compile graphical guest fixtures')
    args = parser.parse_args()
    work = args.prepared.resolve(strict=True)
    native = args.native_build.resolve(strict=True)
    sysroot = work / 'sysroot'
    manifest = json.loads((work / 'manifest.json').read_text())
    run('node', SOURCE / 'test_signature.mjs', work)
    run('cmake', '--build', native, '--target', 'shroot-prepared-fixtures',
        '--parallel', os.environ.get('CMAKE_BUILD_PARALLEL_LEVEL', '4'))
    # These component fixtures run inside the prepared guest as well as natively.
    # A host dynamic loader must not leak into the prepared distribution.
    for name in ('inodes', 'import', 'rpc'):
        header = subprocess.check_output(['readelf', '-l', native / f'libshroot_guest_test_{name}.so'], text=True)
        if 'INTERP' in header:
            parser.error('Prepared component fixtures require SHROOT_STATIC_RUNTIME=ON')
    run('sh', SOURCE / 'build-libc-fixtures.sh', 'glibc', sysroot, work)
    bundle = work / 'bundle'
    if bundle.exists():
        shutil.rmtree(bundle)
    root = bundle / 'rootfs'
    root.mkdir(parents=True)
    for name in ('bin', 'sbin', 'lib', 'etc', 'var', 'usr'):
        source = sysroot / name
        if source.exists() or source.is_symlink():
            copy_tree(source, root / name)
    for name in ('tmp', 'var/log', 'dev/shm', 'usr/bin', 'usr/lib', 'etc'):
        (root / name).mkdir(parents=True, exist_ok=True)
    for source in work.glob('md-*-fixture'):
        shutil.copy2(source, root / 'usr/bin' / source.name)
    shutil.copy2(work / 'md-sandbox-fixture', work / 'md-sandbox-guest-fixture')
    shutil.copy2(work / 'md-fixture', root / 'usr/bin/md-fixture')
    shutil.copy2(work / 'md-fixture.so', root / 'usr/lib/md-fixture.so')
    for name in ('inodes', 'import', 'rpc'):
        shutil.copy2(native / f'libshroot_guest_test_{name}.so', root / f'usr/bin/md-{name}-fixture')
    for name in ('bootstrap', 'supervisor', 'run', 'service', 'image'):
        shutil.copy2(native / f'libshroot_guest_{name}.so', bundle)
    shutil.copy2(native / 'libshroot_guest_capabilities.so', bundle / 'md-capabilities-test')
    for name in ('await-exit', 'command-test', 'sockets-test', 'lifecycle-test',
                 'notification-test', 'notification-lifecycle-test', 'exec-policy-test', 'ipc-launch', 'trace-fault',
                 'sandbox-native-test'):
        shutil.copy2(native / f'md-{name}', bundle)
    shutil.copy2(SOURCE / 'fixtures/md-guest-fixture', root / 'etc')
    for name in ('md-script', 'md-prepare-applications'):
        target = root / 'usr/bin' / name
        shutil.copy2(SOURCE / 'fixtures' / name, target)
        target.chmod(0o755)
    for name in ('package', 'package-update'):
        stage = work / name
        if stage.exists():
            shutil.rmtree(stage)
        shutil.copytree(SOURCE / 'fixtures' / name, stage, symlinks=True)
        if name == 'package-update':
            shutil.copy2(SOURCE / 'fixtures/package/DEBIAN/postrm', stage / 'DEBIAN')
        for script in (stage / 'DEBIAN').iterdir():
            if script.name in ('postinst', 'postrm'):
                script.chmod(0o755)
        (stage / 'DEBIAN').chmod(0o755)
        suffix = 'fixture' if name == 'package' else 'update'
        run('dpkg-deb', '--root-owner-group', '-Zxz', '--build', stage, root / f'tmp/md-package-{suffix}.deb')
    gzip = next(item for item in manifest['packages'] if item['name'] == 'gzip')
    shutil.copy2(work / Path(gzip['file']).name, root / 'tmp/md-hardlinks.deb')
    if args.graphics:
        run('sh', SOURCE / 'build-graphics-fixtures.sh', sysroot, root / 'usr/bin', work)
    shutil.copy2(work / 'manifest.json', bundle)
    with tarfile.open(work / 'bundle.tar.gz', 'w:gz', compresslevel=1, dereference=False) as archive:
        archive.add(bundle, arcname='.')
    print(work / 'bundle.tar.gz')


if __name__ == '__main__':
    main()
