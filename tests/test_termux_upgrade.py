#!/usr/bin/env python3
"""Exercise two local Termux .debs against private APT state and an Alpine rootfs."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def output(*args):
    return subprocess.check_output(args, text=True).strip()


def exercise(work, older, newer, rootfs):
    prefix = Path(os.environ['PREFIX'])
    assert prefix.is_absolute() and output('dpkg', '--print-architecture') == 'aarch64'
    versions = [output('dpkg-deb', '-f', deb, 'Version') for deb in (older, newer)]
    subprocess.run(['dpkg', '--compare-versions', versions[0], 'lt', versions[1]], check=True)
    root, db = work / 'root', work / 'dpkg'
    staged = root / prefix.relative_to('/')
    library = staged / 'var/lib/shroot'
    for path in (root, db, library.parent, work/'apt/lists/partial',
                 work/'cache/archives/partial', work/'log', work/'empty'):
        path.mkdir(parents=True, exist_ok=True)
    (db/'status').touch()
    apt = ['apt-get', '-y']
    for option in (f'Dir::State={work}/apt', f'Dir::State::status={db}/status',
                   f'Dir::Cache={work}/cache', f'Dir::Log={work}/log',
                   'Dir::Etc::sourcelist=/dev/null', f'Dir::Etc::sourceparts={work}/empty',
                   f'DPkg::Options::=--instdir={root}', f'DPkg::Options::=--admindir={db}',
                   f'DPkg::Options::=--log={work}/dpkg.log'):
        apt += ['-o', option]
    cli = staged / 'bin/shroot'
    for deb, version in zip((older, newer), versions):
        subprocess.run([*apt, 'install', str(deb)], check=True)
        assert output('dpkg-query', f'--admindir={db}', '-W', '-f=${Version}', 'shroot') == version
        assert output(cli, '--print-library') == str(prefix/'var/lib/shroot')
        guest = [cli, '--library', library]
        if deb == older:
            subprocess.run([*guest, 'install', rootfs, '--rootfs', '--name', 'alpine'], check=True)
            identity = json.loads(output(*guest, 'resolve', 'alpine'))
            subprocess.run([*guest, 'exec', 'alpine', '--', '/bin/sh', '-ec',
                            'test -s /etc/alpine-release; echo kept >/root/upgrade-marker'], check=True)
        else:
            assert json.loads(output(*guest, 'resolve', 'alpine')) == identity
            assert output(*guest, 'exec', 'alpine', '--', '/bin/cat', '/root/upgrade-marker') == 'kept'
    print(f'PASS APT {versions[0]} -> {versions[1]}: Alpine {identity["id"]} and guest file retained')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('older', type=Path)
    parser.add_argument('newer', type=Path)
    parser.add_argument('alpine_rootfs', type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='shroot-upgrade-') as temporary:
        exercise(Path(temporary), args.older.resolve(strict=True), args.newer.resolve(strict=True),
                 args.alpine_rootfs.resolve(strict=True))
