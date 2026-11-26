#!/usr/bin/env python3
"""Exercise shared runtime/application runners through the local executor."""
import argparse
import errno
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from client_fixture import archive_fixture
from rootfs_oci_fixture import write_layout
from test_oci_services import Server, Suite


def records(lines, prefix):
    return [json.loads(line.removeprefix(prefix)) for line in lines if line.startswith(prefix)]


def launch_controls(suite, build, store, entry):
    controls = suite.report['launchPolicyControls'] = {}
    fixture = str(build / 'client-guest')
    guest = '/bin/client-guest'
    cases = [
            ('direct', [], ['priority-baseline']),
            ('exec-nnp', [fixture, 'exec-nnp'], ['priority-allowed']),
            ('guest-exec-nnp', [], ['exec-nnp', guest, 'priority-allowed']),
            ('exec-allow-priority', [fixture, 'exec-allow-priority'], ['priority-allowed']),
            ('exec-deny-priority', [fixture, 'exec-deny-priority'], ['priority-denied']),
            ('guest-filter', [], ['install-guest-policy'])]
    if entry:
        cases.append(('default-nnp', [fixture, 'exec-nnp'], ['priority-allowed']))
    for policy, prefix, args in cases:
        if policy == 'default-nnp':
            command = suite.image_command('run', store, '--statistics', '--', guest, *args)
            requested = 'default'
        else:
            options = [] if entry else ['--statistics']
            command = suite.run(store, *options, '--', guest, *args)
            requested = 'lazy' if entry else 'base'
        output = suite.command([*prefix, *command])
        lines = output.splitlines()
        assert args[-1] in lines, output
        admission, = records(lines, 'SHROOT_ENTRY_ADMISSION ')
        effects = records(lines, 'SHROOT_TEST_POLICY ')
        completed = sum(item['completed'] for item in records(lines, 'SVC_RUNTIME_STATS '))
        controls[policy] = dict(result=args[-1], admission=admission, effects=effects, lazyCompleted=completed)
        assert admission['requestedMode'] == requested, admission
        if not entry:
            assert admission['admittedMode'] == 'base' and admission['reason'] == 'base-requested', admission
        if completed:
            assert admission['admittedMode'] == 'lazy', admission
        counts = [item['guestFilters'] for item in effects]
        expected_counts = ([0, 1, 1, 1, 2] if policy == 'guest-filter' else
                           [0, 1] if policy == 'exec-deny-priority' else [0])
        assert counts == expected_counts, (policy, effects)
        for item in effects:
            expected_errno = errno.EACCES if policy == 'exec-deny-priority' or item['guestFilters'] else 0
            assert item['getpriorityErrno'] == item['taggedGetuidErrno'] == expected_errno, (policy, item)
    # Setting NNP alone does not change the inherited filter chain. Compare
    # the actual launch observations rather than assuming a host filter count.
    fields = ('seccompMode', 'queryErrno', 'visibleFilters', 'backingFilters', 'hostFiltered')
    direct = controls['direct']['admission']
    for policy in ('exec-nnp', 'default-nnp') if entry else ('exec-nnp',):
        observed = controls[policy]['admission']
        assert observed['noNewPrivs'] == 1, (policy, observed)
        for field in fields:
            assert direct[field] == observed[field], (policy, field, direct, observed)
    # The added allow and deny filters look the same to the launching
    # supervisor. Their effects, checked above, must remain distinguishable.
    allow = controls['exec-allow-priority']['admission']
    deny = controls['exec-deny-priority']['admission']
    for field in ('noNewPrivs', *fields):
        assert allow[field] == deny[field], (field, allow, deny)
    return controls


def check_profile(build, root, layout, native_reserve, profile, entry, policy_only):
    suite = Suite(root / 'reports', build, machine_entry=entry,
                  kernel_profile=profile, executor='local')

    def workload(store):
        metadata = root / f'metadata-{profile}-{int(entry)}'
        metadata.mkdir()
        launch = [str(build / 'client-guest'), 'exec-nnp'] if profile == 'linux-5.15' else []
        if profile == 'native' and not entry:
            output = suite.command(suite.run(store, '--statistics', '--', '/bin/client-guest', 'exec-request-lazy'))
            assert 'priority-baseline' in output.splitlines(), output
            assert 'MD_CPU supervisor ' in output, 'Missing supervisor statistics'
            assert not any(line.startswith('SVC_RUNTIME_STATS ') for line in output.splitlines()), (
                'Guest exec enabled machine entry in a Base launch')
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

    try:
        store = suite.prepare('fixture', layout)
        policy_controls = launch_controls(suite, build, store, entry)
        if not policy_only:
            workload(store)
        if entry:
            completed = {name: control['lazyCompleted'] for name, control in policy_controls.items()}
            missing = {name: policy_controls[name]['admission']['reason']
                       for name, count in completed.items() if not count}
            assert not missing, f'Lazy SVC completions: {completed}; missing: {missing}'
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
    parser.add_argument('--launch-policy-only', action='store_true', help='Only run the launch policy controls')
    args = parser.parse_args()
    build = args.build.resolve()
    native_reserve = None
    if not args.launch_policy_only:
        native_reserve = subprocess.run([build / 'client-guest', 'reserve-large-range']).returncode
        assert native_reserve in (0, 77), native_reserve
    with tempfile.TemporaryDirectory(prefix='shroot-native-suite-') as temporary:
        root = Path(temporary)
        archive = root / 'rootfs.tar.gz'
        binaries = [] if args.launch_policy_only else [(build / 'libshroot_guest_resource_guest.so', 'bin/resource-guest')]
        archive_fixture(build, archive, binaries=binaries)
        layout = root / 'layout'
        write_layout([archive], layout)
        # Independent profiles share only the immutable image input. A failed
        # assertion is reported for its profile without suppressing later ones.
        cases = unittest.TestSuite()
        for profile in ('native', 'linux-5.15'):
            for entry in (False, True):
                def run(profile=profile, entry=entry):
                    check_profile(build, root, layout, native_reserve, profile, entry, args.launch_policy_only)
                cases.addTest(unittest.FunctionTestCase(run, description=f'{profile}, lazy={entry}'))
        return unittest.TextTestRunner(verbosity=2).run(cases).wasSuccessful()


if __name__ == '__main__':
    raise SystemExit(0 if main() else 1)
