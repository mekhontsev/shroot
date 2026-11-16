#!/usr/bin/env python3
"""Qualify the installed default bundle, including relocation and ELF dependencies."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from bundle_layout import audit_bundle


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
        metadata = audit_bundle(relocated, args.readelf)
        for name in metadata['helpers'].values():
            assert os.access(relocated / 'libexec/shroot' / name, os.X_OK), name
        cli = relocated / 'bin/shroot'
        version = subprocess.check_output([str(cli), '--version'], text=True, timeout=10)
        assert metadata['version'] == version.strip()
        subprocess.run([sys.executable, str(Path(__file__).with_name('test_client_runtime.py')),
                        str(build), '--prefix', str(relocated)], check=True, timeout=180)
        print('PASS relocated installed bundle: static dependencies, stripped helpers, API and CLI execution')


if __name__ == '__main__':
    main()
