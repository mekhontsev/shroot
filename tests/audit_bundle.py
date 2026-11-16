#!/usr/bin/env python3
"""Verify a default runtime archive without executing any target code."""
import argparse
import hashlib
from pathlib import Path, PurePosixPath
import tarfile
import tempfile

from bundle_layout import audit_bundle


def audit_archive(archive, readelf, **options):
    archive = Path(archive).resolve()
    digest, filename = Path(str(archive) + '.sha256').read_text().strip().split(maxsplit=1)
    assert filename == archive.name, 'Checksum must name exactly this artifact'
    with archive.open('rb') as stream:
        assert hashlib.file_digest(stream, 'sha256').hexdigest() == digest, 'Archive checksum mismatch'
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
    args = parser.parse_args()
    metadata = audit_archive(args.archive, args.readelf, production=args.production,
                             system=args.system, version=args.version)
    print('PASS archive integrity and ELF layout:', metadata['version'], metadata['system'],
          'testHooks=' + str(metadata['testHooks']), '(target code not executed)')


if __name__ == '__main__':
    main()
