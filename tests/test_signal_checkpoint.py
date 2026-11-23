#!/usr/bin/env python3
"""Native controls for the signal-transparent Shroot protocol."""
import argparse
import hashlib
from pathlib import Path
import re
import statistics
from test_oci_services import Suite
from benchmark_cpu import observe_suite_cpu
from fixture_executor import FixtureExecutor, add_external_watchdog, probe_native_capability


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    FixtureExecutor.add_argument(parser)
    add_external_watchdog(parser)
    parser.add_argument('--copy-fault', action='store_true',
                        help='Run invalid-pointer controls and isolated copy costs only')
    parser.add_argument('--mode', choices=('all', 'controls', 'benchmark'), default='all')
    args = parser.parse_args()
    if args.external_watchdog and args.executor != 'local':
        parser.error('--external-watchdog requires the local executor')
    if args.copy_fault and args.mode != 'all':
        parser.error('--copy-fault cannot be combined with --mode')
    mode = 'copy-fault' if args.copy_fault else args.mode
    suite = Suite(Path('build/signal-checkpoints') / mode, args.build.resolve(), executor=args.executor)
    try:
        suite.report['suiteMode'] = mode
        suite.report['kernel'] = suite.command(['uname', '-r'], quiet=True).strip()
        binary = suite.base + '/signal-checkpoint'
        source = args.build / 'libshroot_guest_test_signal_checkpoint.so'
        with source.open('rb') as stream:
            suite.report['fixtureSha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
        suite.upload(source, binary)
        suite.chmod('700', binary)
        native_skip = args.copy_fault or probe_native_capability(
            suite.observe, suite.report, binary, 'syscall-skip')
        options = ['--copy-fault'] if args.copy_fault else [] if native_skip else ['--without-syscall-skip']
        if args.mode != 'all':
            options.append('--' + args.mode + '-only')
        with observe_suite_cpu(suite) as cpu:
            suite.report['cpu'] = cpu
            output = suite.command([binary, *options], timeout=None if args.external_watchdog else 80)
        if args.copy_fault:
            assert f'PASS copy fault controls: uid={suite.executor.uid}' in output
            assert 'PASS kernel copy: 72 controls;' in output
            assert 'LIMIT service copy fault:' in output
            assert 'LIMIT kernel copy seccomp:' in output
            timings = {}
            for mode, value in re.findall(r'mode=([\w-]+) 32768_copies_128_bytes_ms=([\d.]+)', output):
                timings.setdefault(mode, []).append(float(value))
            assert len(timings) == 4 and all(len(values) == 5 for values in timings.values())
            suite.report['copyMilliseconds'] = {
                mode: {'samples': values, 'median': statistics.median(values)}
                for mode, values in timings.items()
            }
            suite.report['copyBenchmark'] = {
                'copiesPerSample': 32768, 'bytesPerCopy': 128,
                'scope': 'isolated native copy, not end-to-end Shroot',
                'pidLookup': 'cached outside timing',
            }
            suite.report['limitations'] = [line for line in output.splitlines() if line.startswith('LIMIT ')]
            suite.report['passed'] = True
            return
        if args.mode != 'benchmark':
            assert 'PASS checkpoints:' in output and f'uid={suite.executor.uid}' in output
            assert 'PASS checkpoint group stops:' in output
            assert 'PASS terminal stop replacement:' in output
            assert 'PASS birth stop replacement:' in output
            assert 'PASS SYSEMU strict policy:' in output
            assert 'PASS SYSEMU native admission:' in output
            assert 'PASS SYSEMU pending signals:' in output
            assert 'PASS SYSEMU interrupted IO:' in output
            assert 'PASS SYSEMU signal replay:' in output
            assert 'PASS SYSEMU register copy:' in output
            assert 'PASS native entry replay:' in output
            assert 'PASS chained replay:' in output
            assert 'PASS chained task injection:' in output
            assert 'PASS chained intervening stops:' in output
            assert 'PASS chained process pending:' in output
            assert 'PASS retained job control:' in output
            assert 'LIMIT service copy fault:' in output
            assert 'LIMIT checkpoint during replay:' in output
            assert 'LIMIT regenerated job control:' in output
            assert 'PASS task injection admission:' in output
            assert 'PASS unified checkpoint owner:' in output
            assert 'PASS checkpoint borrowing:' in output
            assert 'PASS scalar checkpoint:' in output
        suite.report['limitations'] = [line for line in output.splitlines() if line.startswith('LIMIT ')]
        if args.mode == 'controls':
            suite.report['passed'] = True
            return
        expected_modes = {'brk', 'single-step', 'seccomp-trace', 'sysemu', 'sysemu-context'}
        if native_skip:
            expected_modes.add('syscall')
        timings = {}
        for mode, value in re.findall(r'mode=([\w-]+) 1000_rounds_ms=([\d.]+)', output):
            timings.setdefault(mode, []).append(float(value))
        assert set(timings) == expected_modes and all(len(values) == 5 for values in timings.values())
        suite.report['checkpointMilliseconds'] = {
            mode: {'samples': values, 'median': statistics.median(values)}
            for mode, values in timings.items()
        }
        suite.report['passed'] = True
    finally:
        try:
            suite.command(['rm', '-rf', suite.base])
        finally:
            suite.finish()


if __name__ == '__main__':
    main()
