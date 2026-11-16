#!/usr/bin/env python3
"""Exercise shared runtime/application runners without MagicDesk."""
import argparse
import json
from pathlib import Path
import tempfile

from client_fixture import archive_fixture
from rootfs_oci_fixture import write_layout
from test_oci_services import Server, Suite


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    args = parser.parse_args()
    build = args.build.resolve()
    with tempfile.TemporaryDirectory(prefix='shroot-native-suite-') as temporary:
        root = Path(temporary)
        archive = root / 'rootfs.tar.gz'
        archive_fixture(build, archive)
        layout = root / 'layout'
        write_layout([archive], layout)
        for profile in ('native', 'linux-5.15'):
            for entry in (False, True):
                suite = Suite(root / 'reports', build, machine_entry=entry,
                              kernel_profile=profile, executor='local')
                try:
                    store = suite.prepare('fixture', layout)
                    suite.command(suite.guest(store, '--', '/bin/client-guest', 'exit42'), expected=42)
                    output = suite.command(suite.run(store, '--env', "LIBSHROOT_TEST=retained ' value",
                        '--', '/bin/client-guest', "spaces ' ; $(false)"))
                    assert 'PASS guest: arguments, environment, metadata and descriptor isolation' in output
                    info = json.loads(suite.stdout(suite.image_command('inspect', store)))
                    assert info['format'] == 17
                    # Use the same readiness/completion owner as real OCI services.
                    server = Server(suite, suite.run(store, '--', '/bin/client-guest', 'hold'), timeout=30)
                    try:
                        server.ready('ready', timeout=15)
                        server.executor.cancel()
                        server.process.join(15)
                        assert not server.process.is_alive(), 'cancelled guest tree did not terminate'
                    finally:
                        server.close()
                    assert not suite.command(suite.image_command('launches', store), quiet=True).strip()
                    suite.report['passed'] = True
                finally:
                    suite.finish()
                assert not Path(suite.base).exists(), 'fixture store was not removed'
                assert json.loads(suite.output.read_text())['passed']
                print(f'PASS shared native suite: entry={entry} profile={profile}', flush=True)


if __name__ == '__main__':
    main()
