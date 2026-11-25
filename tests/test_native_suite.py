#!/usr/bin/env python3
"""Exercise shared runtime/application runners through the local executor."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from client_fixture import archive_fixture
from rootfs_oci_fixture import write_layout
from test_oci_services import Server, Suite


def check_profile(build, root, layout, native_reserve, profile, entry):
    metadata = root / f'metadata-{profile}-{int(entry)}'
    metadata.mkdir()
    fixture = str(build / 'client-guest')
    launch = [fixture, 'exec-nnp'] if profile == 'linux-5.15' else []
    suite = Suite(root / 'reports', build, machine_entry=entry,
                  kernel_profile=profile, executor='local')
    try:
        store = suite.prepare('fixture', layout)
        policy_controls = suite.report['launchPolicyControls'] = {}
        for policy, expected in (('exec-nnp', 'priority-allowed'), ('exec-deny-priority', 'priority-denied')):
            evidence = suite.report.get('machineEntry')
            before = evidence['completed'] if evidence is not None else 0
            output = suite.command([fixture, policy, *suite.run(store, '--', '/bin/client-guest', expected)])
            assert expected in output.splitlines(), output
            control = policy_controls[policy] = {'result': expected}
            if evidence is not None:
                control['lazyCompleted'] = evidence['completed'] - before
        if profile == 'native' and not entry:
            output = suite.command([str(build / 'libshroot_guest_resource_guest.so'),
                                    'native-metadata', str(metadata)])
            assert 'PASS native metadata:' in output
        output = suite.command([*launch, *suite.run(store, '--bind-create', str(metadata), '/native-metadata',
            '--', '/bin/resource-guest', 'native-metadata', '/native-metadata')])
        assert 'PASS native metadata:' in output
        suite.command([*launch, *suite.guest(store, '--', '/bin/client-guest', 'exit42')], expected=42)
        if profile == 'native' and native_reserve == 0:
            suite.command(suite.guest(store, '--', '/bin/client-guest', 'reserve-large-range'))
        output = suite.command([*launch, *suite.run(store, '--env', "LIBSHROOT_TEST=retained ' value",
            '--', '/bin/client-guest', "spaces ' ; $(false)")])
        assert 'PASS guest: arguments, environment, metadata and descriptor isolation' in output
        info = json.loads(suite.stdout(suite.image_command('inspect', store)))
        assert info['format'] == 17
        # Use the same readiness/completion owner as real OCI services.
        server = Server(suite, [*launch, *suite.run(store, '--', '/bin/client-guest', 'hold')], timeout=30)
        try:
            server.ready('ready', timeout=15)
            server.executor.cancel()
            server.process.join(15)
            assert not server.process.is_alive(), 'cancelled guest tree did not terminate'
        finally:
            server.close()
        assert not suite.command(suite.image_command('launches', store), quiet=True).strip()
        if entry:
            assert policy_controls['exec-nnp']['lazyCompleted'] > 0, (
                'No completed lazy SVC calls in the no_new_privs control')
        suite.report['passed'] = True
    except Exception as error:
        suite.report['failure'] = str(error)
        raise
    finally:
        suite.finish()
    assert not Path(suite.base).exists(), 'fixture store was not removed'
    assert json.loads(suite.output.read_text())['passed']
    print(f'PASS shared native suite: entry={entry} profile={profile}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    build = parser.parse_args().build.resolve()
    native_reserve = subprocess.run([build / 'client-guest', 'reserve-large-range']).returncode
    assert native_reserve in (0, 77), native_reserve
    with tempfile.TemporaryDirectory(prefix='shroot-native-suite-') as temporary:
        root = Path(temporary)
        archive = root / 'rootfs.tar.gz'
        archive_fixture(build, archive, binaries=[
            (build / 'libshroot_guest_resource_guest.so', 'bin/resource-guest')])
        layout = root / 'layout'
        write_layout([archive], layout)
        # Independent profiles share only the immutable image input. A failed
        # assertion is reported for its profile without suppressing later ones.
        cases = unittest.TestSuite()
        for profile in ('native', 'linux-5.15'):
            for entry in (False, True):
                def run(profile=profile, entry=entry):
                    check_profile(build, root, layout, native_reserve, profile, entry)
                cases.addTest(unittest.FunctionTestCase(run, description=f'{profile}, lazy={entry}'))
        return unittest.TextTestRunner(verbosity=2).run(cases).wasSuccessful()


if __name__ == '__main__':
    raise SystemExit(0 if main() else 1)
