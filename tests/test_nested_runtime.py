#!/usr/bin/env python3
"""Exercise guest tracing and nested runtime with the same native helpers."""
import argparse
import itertools
import os
from pathlib import Path
import subprocess
import tempfile
import time

from client_fixture import archive_fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('--case', choices=('debugger', 'signals', 'nested'), default='debugger')
    parser.add_argument('--diagnostics', action='store_true')
    parser.add_argument('--statistics', action='store_true')
    parser.add_argument('--native-control', action='store_true')
    parser.add_argument('--depth', type=int, default=2, help='Runtime levels in the nested case')
    parser.add_argument('--entry', action='append', choices=('0', '1'),
                        help='Select Base (0) or lazy (1); default tests both at every level')
    parser.add_argument('--scenario', action='append', help='Existing debugger fixture scenario[:group]')
    parser.add_argument('--list-scenarios', action='store_true', help='List debugger cases without running fixtures')
    args = parser.parse_args()
    if args.depth < 1:
        parser.error('--depth must be positive')
    build = args.build.resolve()
    cli = [str(build / 'shroot'), '--runtime', str(build)]
    scenarios = args.scenario or [
        'syscall', 'syscall-info',
        *('syscall-signal:' + group for group in ('stat', 'poll', 'epoll')),
        'syscall-suspend', 'mixed',
        *('seccomp-trace:' + group for group in
          ('install', 'getpid', 'getuid', 'openat', 'getpgid', 'sigmask', 'skip')),
        'syscall-emulation', 'seccomp-interrupt', 'pidfd-copy', 'proc-fd', 'proc-thread',
        'service-gates', 'pending-peek', 'owner-exit', 'exitkill', 'exitkill-terminal']
    if args.list_scenarios:
        print('\n'.join(scenarios))
        return
    print(f'HOST uid={os.getuid()} gid={os.getgid()} kernel={os.uname().release} '
          f'machine={os.uname().machine} page_size={os.sysconf("SC_PAGE_SIZE")}', flush=True)

    def run(argv, expected=0):
        print('RUN', *map(str, argv), flush=True)
        started = time.monotonic()
        result = subprocess.run(argv, timeout=60)
        assert result.returncode == expected, result
        print(f'PASS exit={result.returncode} elapsed={time.monotonic() - started:.3f}s', flush=True)
        return result

    signal_fixtures = {'signal_delivery': [()],
                       'svc_machine_signal': [('--group', name) for name in ('frame', 'alias', 'native', 'kernel')],
                       'signal_checkpoint': [('--checkpoint-borrow',), ('--terminal-race',)]}
    if args.native_control and args.case == 'signals':
        for fixture, cases in signal_fixtures.items():
            for case in cases:
                run([str(build / f'libshroot_guest_test_{fixture}.so'), *case])
    elif args.native_control:
        with tempfile.NamedTemporaryFile(prefix='shroot-debugger-') as data:
            data.write(b'shroot syscall fixture\n')
            data.flush()
            for scenario in scenarios:
                run([str(build / 'libshroot_guest_debugger_guest.so'), '--native-control', *scenario.split(':'),
                     *([data.name] if scenario == 'syscall' else [])])
    binaries = [(build / 'libshroot_guest_debugger_guest.so', 'bin/debugger')] if args.case == 'debugger' else []
    if args.case == 'signals':
        binaries = [(build / f'libshroot_guest_test_{fixture}.so', f'bin/{fixture}')
                    for fixture in signal_fixtures]
    for name in (('run', 'supervisor', 'service', 'bootstrap') if args.case == 'nested' else ()):
        binary = 'libshroot_guest_' + name + '.so'
        binaries.append((build / binary, 'runtime/' + binary))
    with tempfile.TemporaryDirectory(prefix='shroot-nested-') as directory:
        root = Path(directory)
        archive_fixture(build, root / 'rootfs.tar', binaries=binaries)
        run(cli + ['rootfs', str(root / 'rootfs.tar'), str(root / 'image')])
        run(cli + ['create', str(root / 'image'), str(root / 'outer')])
        for level in range(1, args.depth if args.case == 'nested' else 1):
            run(cli + ['create', str(root / 'image'), str(root / f'level-{level}')])
        entries_to_test = args.entry or ('0', '1')
        for entry in entries_to_test:
            command = cli + ['exec', str(root / 'outer'), '--env', 'SHROOT_MACHINE_ENTRY=' + entry]
            if args.diagnostics:
                command += ['--diagnostics']
            if args.statistics:
                command += ['--statistics']
            if args.case == 'debugger':
                for scenario in scenarios:
                    run(command + ['--', '/bin/debugger', *scenario.split(':')])
            elif args.case == 'signals':
                for fixture, cases in signal_fixtures.items():
                    for case in cases:
                        run(command + ['--', f'/bin/{fixture}', *case])
                # Guest cancellation must work even when Android's inherited
                # native policy rejects syscall -1 outside the runtime.
                run(command + ['--', '/bin/signal_checkpoint', '--syscall-stop-restore'])
            else:
                for entries in itertools.product(entries_to_test, repeat=args.depth-1):
                    nested = command + ['--user', str(os.getuid()) + ':' + str(os.getgid()),
                                        '--bind-create', str(root), '/nested']
                    for level, inner in enumerate(entries, start=1):
                        nested += ['--', '/runtime/libshroot_guest_run.so']
                        if args.diagnostics:
                            nested += ['--diagnostics']
                        if args.statistics:
                            nested += ['--statistics']
                        nested += ['--store', f'/nested/level-{level}', '--env',
                                   'SHROOT_MACHINE_ENTRY=' + inner]
                        if level < args.depth-1:
                            nested += ['--bind-create', '/nested', '/nested']
                    nested += ['--env', "LIBSHROOT_TEST=retained ' value", '--', '/bin/client-guest']
                    run(nested + ['exit42'], expected=42)
                    run(nested + ['fork-exec', 'exit42'], expected=42)
                    run(nested + ['fork-exec', "spaces ' ; $(false)"])


if __name__ == '__main__':
    main()
