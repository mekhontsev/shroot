"""Shared command transport preserves executor selection and test evidence."""
from pathlib import Path
import shlex
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

lab = Path(__file__).resolve().parents[1]
with patch.object(sys, 'path', [str(lab), *sys.path]):
    from client_fixture import archive_fixture
    from kernel_profile import KernelProfile
    from test_oci_services import Suite
    from test_debugger_runtime import outcome
    from test_ipc_credentials_runtime import custody_cases
    from list_unittests import cases as unittest_cases
    import test_nested_runtime
    import test_bundle


class GuestFixtureTest(unittest.TestCase):
    def test_dynamic_rootfs_keeps_loader_and_library_aliases_without_host_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            program = root / 'client-guest'
            program.write_bytes(b'probe')
            program.chmod(0o700)
            loader = root / 'ld.so'
            loader.write_bytes(b'loader')
            library = root / 'libprobe.so.1.2'
            library.write_bytes(b'library')
            alias = root / 'libprobe.so.1'
            alias.symlink_to(library.name)
            archive = root / 'rootfs.tar.gz'
            listing = (f'linux-vdso.so.1 (0x1)\nlibprobe.so.1 => {alias} (0x2)\n'
                       f'{loader} (0x3)\n')
            with patch('client_fixture.elf_details', return_value=f'[Requesting program interpreter: {loader}]'), \
                    patch('client_fixture.subprocess.check_output', return_value=listing):
                archive_fixture(root, archive, binaries=[(program, 'bin/one'), (program, 'bin/two')])
            with tarfile.open(archive) as tar:
                entry = tar.getmember('bin/client-guest')
                self.assertEqual((entry.mode, entry.uid, entry.gid), (0o755, 0, 0))
                for path, expected in ((loader, b'loader'), (alias, b'library')):
                    name = str(path.relative_to('/'))
                    self.assertEqual(tar.getnames().count(name), 1)
                    self.assertTrue(tar.getmember(name).isfile())
                    self.assertEqual(tar.extractfile(name).read(), expected)

    def test_nested_case_discovery_has_no_runtime_side_effects(self):
        with patch.object(sys, 'argv', ['nested', '/missing-build', '--list-scenarios']), \
                patch('test_nested_runtime.subprocess.run') as run, \
                patch('test_nested_runtime.archive_fixture') as archive, patch('builtins.print') as output:
            test_nested_runtime.main()
        run.assert_not_called()
        archive.assert_not_called()
        names = output.call_args.args[0].splitlines()
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual({'stat', 'poll', 'epoll'},
                         {name.split(':')[1] for name in names if name.startswith('syscall-signal:')})
        self.assertEqual({'install', 'getpid', 'getuid', 'openat', 'getpgid', 'sigmask', 'skip'},
                         {name.split(':')[1] for name in names if name.startswith('seccomp-trace:')})

    def test_prebuilt_bundle_relocation_does_not_install_or_modify_its_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'read only bundle'
            source.mkdir()
            (source / 'payload').write_text('unchanged')
            (source / 'alias').symlink_to('payload')

            def audit(prefix, readelf):
                self.assertNotEqual(prefix, source)
                self.assertEqual('relocated bundle', prefix.name)
                self.assertEqual('unchanged', (prefix / 'payload').read_text())
                self.assertEqual(Path('payload'), (prefix / 'alias').readlink())
                return dict(version='test', helpers={})

            with patch.object(sys, 'argv', ['bundle', '/read-only-build', '--prefix', str(source), '--case', 'cli']), \
                    patch('test_bundle.audit_bundle', side_effect=audit), \
                    patch('test_bundle.subprocess.check_output', return_value='test\n'), \
                    patch('test_bundle.subprocess.run') as run, patch('builtins.print'):
                test_bundle.main()
            run.assert_called_once()
            self.assertTrue(run.call_args.args[0][1].endswith('test_client_runtime.py'))
            self.assertEqual(['--case', 'cli'], run.call_args.args[0][-2:])
            self.assertEqual('unchanged', (source / 'payload').read_text())
            self.assertEqual(Path('payload'), (source / 'alias').readlink())

    def test_nested_workloads_stage_only_their_inputs_in_private_storage(self):
        workloads = (
            (['--case', 'debugger', '--scenario', 'syscall-info'], ['bin/debugger'], 1),
            (['--case', 'debugger', '--scenario', 'seccomp-trace:openat'], ['bin/debugger'], 1),
            (['--case', 'signals'], ['bin/signal_delivery', 'bin/svc_machine_signal', 'bin/signal_checkpoint'], 1),
            (['--case', 'nested', '--depth', '3'],
             ['runtime/libshroot_guest_' + name + '.so' for name in ('run', 'supervisor', 'service', 'bootstrap')], 3))
        for options, binaries, stores in workloads:
            with self.subTest(options=options), patch.object(sys, 'argv',
                    ['nested', '/read-only-build', '--entry', '0', *options]), \
                    patch('test_nested_runtime.tempfile.TemporaryDirectory') as temporary, \
                    patch('test_nested_runtime.archive_fixture') as archive, \
                    patch('test_nested_runtime.subprocess.run') as run, patch('builtins.print'):
                temporary.return_value.__enter__.return_value = '/private-work'
                run.side_effect = lambda argv, **kwargs: Mock(returncode=42 if argv[-1] == 'exit42' else 0)
                test_nested_runtime.main()
                self.assertNotIn('dir', temporary.call_args.kwargs)
                self.assertEqual(binaries, [name for _, name in archive.call_args.kwargs['binaries']])
                commands = [call.args[0] for call in run.call_args_list]
                self.assertEqual(stores, sum('create' in command for command in commands))
                self.assertTrue(all(call.kwargs['timeout'] == 60 for call in run.call_args_list))
                if 'seccomp-trace:openat' in options:
                    self.assertEqual(['seccomp-trace', 'openat'], commands[-1][-2:])
                if options[1] == 'signals':
                    groups = [command[-1] for command in commands if '--group' in command]
                    self.assertEqual(['frame', 'alias', 'native', 'kernel'], groups)

    def test_ctest_discovers_independent_cases_without_executing_them(self):
        fixture = type('Fixture', (unittest.TestCase,), {
            '__module__': '_fixture', 'test_first': lambda self: None,
            'test_second': lambda self: None})
        suite = unittest.TestSuite([
            unittest.TestSuite([fixture('test_first')]),
            unittest.TestSuite([unittest.TestSuite([fixture('test_second')])])])
        with patch.object(unittest.TestCase, 'run', side_effect=AssertionError('discovery ran a test')):
            self.assertEqual(['Fixture.test_first', 'Fixture.test_second'], list(unittest_cases(suite)))
        self.assertEqual(2, suite.countTestCases())

    def test_ipc_custody_matrix_is_shared_and_complete(self):
        native, guest = ['/native', '--custody-native'], ['/runner', '--', '/guest', '--custody']
        cases = list(custody_cases(native, guest))
        self.assertEqual(20, len(cases))
        self.assertEqual(20, len({name for name, _ in cases}))
        for index, (name, argv) in enumerate(cases):
            receive, protected, is_guest = index // 4, index // 2 % 2, bool(index % 2)
            self.assertEqual(f'ancillary custody receive={receive} protected={protected} guest={is_guest}', name)
            self.assertEqual((guest if is_guest else native) + [str(receive), str(protected)], argv)
        self.assertEqual(['/native', '--custody-native'], native)
        self.assertEqual(['/runner', '--', '/guest', '--custody'], guest)

    def suite(self, mode='shell', code=0, output='output\n'):
        suite = Suite.__new__(Suite)
        suite.executor = Mock(mode=mode)
        suite.executor.shell = '/host/bin/sh'
        suite.executor.command_shell = '"$TEST_SHELL"'
        suite.executor.native_path.side_effect = lambda path: '/apk/test' if path == '/fixture/test' else path
        suite.executor.execute.return_value = dict(exitCode=code, output=output)
        suite.executor.client = Mock()
        suite.report = dict(commands=[])
        suite.kernel_profile = KernelProfile('native')
        suite.runner, suite.image = '/run', '/image'
        return suite

    def test_observe_uses_the_selected_executor(self):
        for mode in ('app', 'shell'):
            with self.subTest(mode=mode):
                suite = self.suite(mode, 19)
                result = suite.observe(['/fixture/test', 'argument with spaces'], timeout=42, quiet=True)
                self.assertEqual(dict(exitCode=19, output='output\n'), result)
                command, timeout = suite.executor.execute.call_args.args
                self.assertEqual(57, timeout)
                self.assertIn(shlex.quote(shlex.join(['/apk/test', 'argument with spaces'])), command)
                self.assertIn('"$TEST_SHELL" -c ', command)
                suite.client.call.assert_not_called()
                self.assertEqual(19, suite.report['commands'][0]['exitCode'])

    def test_command_requires_the_expected_exit(self):
        suite = self.suite(code=19)
        with self.assertRaises(AssertionError):
            suite.command(['/fixture/test'], quiet=True)
        self.assertEqual('output\n', suite.command(['/fixture/test'], expected=19, quiet=True))
        self.assertEqual(2, len(suite.report['commands']))

    def test_transport_failure_is_not_a_command_result(self):
        suite = self.suite()
        suite.executor.execute.side_effect = TimeoutError('incomplete command')
        with self.assertRaises(TimeoutError):
            suite.observe(['/fixture/test'], quiet=True)
        self.assertEqual([], suite.report['commands'])

    def test_failure_keeps_full_report_without_repeating_large_output(self):
        output = 'begin\n' + 'diagnostic\n' * 4000 + 'end\n'
        suite = self.suite(code=19, output=output)
        with self.assertRaises(AssertionError) as error:
            suite.command(['/fixture/test'], quiet=True)
        self.assertLess(len(str(error.exception)), 10000)
        self.assertEqual(output, suite.report['commands'][0]['output'])
        self.assertIn('end', str(error.exception))

    def test_native_capability_does_not_mask_guest_failures(self):
        for mode in ('app', 'shell'):
            for code in (0, 77, 159):
                with self.subTest(mode=mode, code=code):
                    suite = self.suite(mode, code)
                    with patch('builtins.print'):
                        self.assertEqual(code == 0, suite.native_capability('/fixture/test', 'openat2'))
                    evidence = suite.report['nativeCapabilities'][0]
                    self.assertEqual(code, evidence['exitCode'])
                    self.assertIn('--probe-openat2', suite.report['commands'][0]['command'])
                    if code:
                        with self.assertRaises(AssertionError):
                            suite.command(['/fixture/test', 'resolution'], quiet=True)
        for code in (1, 124, 134, 139):
            with self.subTest(code=code), self.assertRaises(AssertionError):
                self.suite(code=code).native_capability('/fixture/test', 'openat2')

    def test_profile_keeps_raw_evidence_in_report(self):
        suite = self.suite()
        suite.kernel_profile = Mock(options=['--profile'], shell=lambda command: command)
        suite.kernel_profile.output.return_value = 'guest output\n'
        result = suite.observe(['/run', '--store', '/store'], quiet=True)
        suite.kernel_profile.observe.assert_called_once_with('output\n', required=True)
        self.assertEqual('guest output\n', result['output'])
        self.assertEqual('output\n', suite.report['commands'][0]['output'])
        self.assertEqual('output\n', suite.command(['/fixture/test'], quiet=True, raw=True))

    def test_debugger_missing_toolchain_is_not_a_pass(self):
        missing = 'UNAVAILABLE gprof: compiler does not supply gcrt1.o'
        self.assertEqual('unavailable', outcome('gprof', missing)['status'])
        self.assertIsNone(outcome('gprof', missing)['passed'])
        self.assertEqual('failed', outcome('gprof', 'gcc: compilation failed')['status'])
        self.assertEqual('failed', outcome('gdb-attach', missing)['status'])
        self.assertEqual('passed', outcome('gprof', 'PASS gprof')['status'])


if __name__ == '__main__':
    unittest.main()
