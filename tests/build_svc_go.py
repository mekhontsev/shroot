#!/usr/bin/env python3
"""Build the stock-Go stress fixture through the explicitly selected executor."""
import argparse
import hashlib
from pathlib import Path
from test_oci_services import Suite
from fixture_executor import FixtureExecutor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--source', type=Path, default=Path(__file__).with_name('test_svc_go.go'))
    parser.add_argument('--build', type=Path, help='Native runtime bundle; required for local execution')
    environment = parser.add_mutually_exclusive_group()
    environment.add_argument('--cgo-environment', help='Installed MagicDesk environment with a Linux C toolchain')
    environment.add_argument('--cgo-store', help='Explicit inode store with a Linux C toolchain')
    FixtureExecutor.add_argument(parser)
    args = parser.parse_args()
    expected = '94f3e30b8e374bc285e7dadc11e0865726b9bc6e85b841ccceaabc0214c6b7c8'
    assert hashlib.sha256(args.archive.read_bytes()).hexdigest() == expected, 'requires official Go 1.27.2 linux-arm64'
    suite = Suite(args.output.parent / 'svc-go-receipts', args.build, executor=args.executor)
    try:
        suite.upload(args.archive, suite.base + '/go.tar.gz')
        suite.upload(args.source, suite.base + '/probe.go')
        suite.command(['tar', '-xzf', suite.base + '/go.tar.gz', '-C', suite.base], quiet=True)
        suite.command(['mkdir', suite.base + '/tmp', suite.base + '/cache'])
        if args.cgo_environment or args.cgo_store:
            store = suite.installed_environment(args.cgo_environment or 'toolchain', args.cgo_store)['store']
            suite.upload(Path(__file__).with_name('test_svc_cgo.go'), suite.base + '/cgo.go')
            suite.command(suite.guest(store, '--user', '0:0',
                           '--bind', suite.base, '/tmp', '--', '/usr/bin/env',
                           'CGO_ENABLED=1', 'GOTOOLCHAIN=local', 'GOENV=off', 'CC=/usr/bin/cc',
                           'GOROOT=/tmp/go', 'GOCACHE=/tmp/cache', 'GOTMPDIR=/tmp/tmp',
                           '/tmp/go/bin/go', 'build', '-p', '4', '-ldflags=-linkmode=external -extldflags=-static',
                           '-o', '/tmp/probe', '/tmp/probe.go', '/tmp/cgo.go'), timeout=240)
        else:
            suite.command(['env', 'CGO_ENABLED=0', 'GOTOOLCHAIN=local', 'GOENV=off',
                       'GOROOT=' + suite.base + '/go', 'GOCACHE=' + suite.base + '/cache',
                       'GOTMPDIR=' + suite.base + '/tmp',
                       suite.base + '/go/bin/go', 'build', '-p', '4', '-o', suite.base + '/probe',
                       suite.base + '/probe.go'], timeout=240)
        suite.download(suite.base + '/probe', args.output, overwrite=True)
        suite.command(['rm', '-rf', suite.base])
        suite.report['passed'] = True
    finally:
        suite.finish()


if __name__ == '__main__':
    main()
