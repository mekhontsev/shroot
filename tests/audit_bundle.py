#!/usr/bin/env python3
"""Verify a default runtime archive without executing any target code."""
import argparse
import hashlib
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile

from bundle_layout import audit_bundle


def verify_checksum(archive):
    digest, filename = Path(str(archive) + '.sha256').read_text().strip().split(maxsplit=1)
    assert filename == archive.name, 'Checksum must name exactly this artifact'
    with archive.open('rb') as stream:
        assert hashlib.file_digest(stream, 'sha256').hexdigest() == digest, 'Archive checksum mismatch'


def audit_termux_package(archive, prefix, readelf, **options):
    verify_checksum(archive)
    assert prefix.is_absolute() and prefix != Path('/') and '..' not in prefix.parts
    for field, expected in [('Package', 'shroot'), ('Architecture', 'aarch64'),
                            ('Version', options['version'].replace('-', '~'))]:
        value = subprocess.check_output(['dpkg-deb', '-f', archive, field], text=True).strip()
        assert value == expected, (field, value, expected)
    with tempfile.TemporaryDirectory(prefix='shroot-deb-') as directory:
        root = Path(directory)
        subprocess.run(['dpkg-deb', '-x', archive, root], check=True)
        installed = root / prefix.relative_to('/')
        for path in root.rglob('*'):
            if path in installed.parents or path == installed:
                assert path.is_dir() and not path.is_symlink(), path
                continue
            assert path.is_relative_to(installed), path
            assert path.relative_to(installed).parts[0] in ('bin', 'libexec', 'lib', 'include', 'share'), path
        for path in [installed / 'bin/shroot', *(installed / 'libexec/shroot').glob('*.so')]:
            assert path.stat().st_mode & 0o111, ('Non-executable package member', path)
        control = root / 'control'
        subprocess.run(['dpkg-deb', '-e', archive, control], check=True)
        assert {p.name for p in control.iterdir()} <= {'control', 'md5sums'}, 'Unexpected control files'
        return audit_bundle(installed, readelf, **options)


def audit_archive(archive, readelf, **options):
    archive = Path(archive).resolve()
    verify_checksum(archive)
    with tempfile.TemporaryDirectory(prefix='shroot-artifact-') as directory:
        with tarfile.open(archive, 'r:gz') as stream:
            members = stream.getmembers()
            names = [PurePosixPath(member.name) for member in members]
            assert all(name.parts and not name.is_absolute() and '..' not in name.parts
                       and '\\' not in str(name) for name in names), 'Unsafe archive path'
            roots = {name.parts[0] for name in names}
            assert len(roots) == 1, 'Runtime archive must have one top-level directory'
            for member in members:
                if member.isfile() and ('/libexec/shroot/' in member.name and member.name.endswith('.so')
                                        or member.name.endswith('/bin/shroot')):
                    assert member.mode & 0o111, ('Non-executable archive member', member.name)
            stream.extractall(directory, filter='data')
        prefix = Path(directory) / roots.pop()
        assert prefix.is_dir() and not prefix.is_symlink()
        return audit_bundle(prefix, readelf, **options)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--readelf', default='readelf')
    parser.add_argument('--system', choices=('Android', 'Linux'), required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--production', action='store_true')
    parser.add_argument('--termux-prefix', type=Path, help='target installation prefix of a Termux .deb')
    args = parser.parse_args()
    options = dict(production=args.production, system=args.system, version=args.version)
    if args.termux_prefix:
        metadata = audit_termux_package(args.archive, args.termux_prefix, args.readelf, **options)
    else:
        metadata = audit_archive(args.archive, args.readelf, **options)
    print('PASS archive integrity and ELF layout:', metadata['version'], metadata['system'],
          'testHooks=' + str(metadata['testHooks']), '(target code not executed)')


if __name__ == '__main__':
    main()
