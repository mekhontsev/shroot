"""Select a fixture transport without changing identity or test semantics."""
import argparse
import os
import shlex
from host_integration import adapter

MAX_DEADLINE_SECONDS = 7200


def deadline_seconds(value):
    seconds = int(value)
    if not 1 <= seconds <= MAX_DEADLINE_SECONDS:
        raise argparse.ArgumentTypeError(f'deadline must be between 1 and {MAX_DEADLINE_SECONDS} seconds')
    return seconds


def bounded_shell(executor, command, timeout, *, kill_after=None):
    seconds = deadline_seconds(timeout)
    grace = [] if kill_after is None else ['-k', str(deadline_seconds(kill_after))]
    # The native executor owns the deadline and process group. GNU timeout
    # would create a second group outside its cancellation boundary.
    if executor.mode == 'local':
        return command
    return shlex.join(['timeout', *grace, str(seconds)]) + ' ' + command


def add_diagnostics_argument(parser):
    parser.add_argument('--diagnostics', nargs='?', const='all', choices=('all', 'signals'),
                        help='Record Shroot transitions or only guest faults/abnormal exits; not for timing')


def diagnostic_options(mode):
    return ['--diagnostics' if mode == 'all' else '--diagnostics=signals'] if mode else []


def probe_native_capability(observe, report, fixture, name):
    result = observe([fixture, '--probe-' + name], quiet=True, timeout=30)
    assert result['exitCode'] in (0, 77, 159), result
    available = result['exitCode'] == 0
    report.setdefault('nativeCapabilities', []).append(
        dict(fixture=fixture, capability=name, available=available, **result))
    if not available:
        print('UNAVAILABLE native ' + name + ': ' + str(result), flush=True)
    return available


class FixtureExecutor:
    choices = ('local', 'shell', 'app')

    @classmethod
    def add_argument(cls, parser, *, android_only=False):
        choices = ('shell', 'app') if android_only else cls.choices
        parser.add_argument('--executor', choices=choices,
                            default=os.environ.get('SHROOT_TEST_EXECUTOR', 'shell' if android_only else 'local'),
                            help='Host execution identity; local keeps the calling process UID')

    @classmethod
    def connect(cls, output, mode=None, prefix='fixture', *, config=None, server=None):
        mode = mode or os.environ.get('SHROOT_TEST_EXECUTOR', 'local')
        if mode == 'local':
            from executors.local import LocalExecutor
            return LocalExecutor(output, prefix)
        if mode in ('shell', 'app'):
            return adapter().executor(output, mode, prefix, config=config, server=server)
        raise ValueError('Unknown fixture executor: ' + mode)
