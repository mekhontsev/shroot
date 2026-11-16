#!/usr/bin/env python3
"""Native transport contracts, without an APK or an MCP configuration."""
import argparse
import os
from pathlib import Path
import queue
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from fixture_executor import FixtureExecutor


class LocalCommands(unittest.TestCase):
    def setUp(self):
        self.output = tempfile.TemporaryDirectory(prefix='shroot-transport-')
        self.addCleanup(self.output.cleanup)
        with mock.patch('executors.magicdesk.connect', side_effect=AssertionError('MCP used')):
            self.executor = FixtureExecutor.connect(self.output.name, 'local')
        self.addCleanup(self.executor.close)

    def test_identity_and_private_cwd(self):
        result = self.executor.execute('id -u; pwd; printf "%s" "$TMPDIR"')
        self.assertEqual(result, dict(exitCode=0, output=f'{os.getuid()}\n{self.executor.root}\n{self.executor.root}'))
        self.assertEqual(self.executor.evidence['uid'], os.getuid())
        self.assertEqual(self.executor.evidence['kernel'], os.uname().release)
        self.assertEqual(self.executor.evidence['pageSize'], os.sysconf('SC_PAGE_SIZE'))
        self.assertIsNone(self.executor.console)

    def test_full_output_and_exit_are_not_replayed(self):
        script = ('from pathlib import Path; import sys; '
                  'p=Path("count"); assert not p.exists(); p.touch(); '
                  'sys.stdout.write("x" * 1000000); sys.stdout.flush(); '
                  'sys.stderr.write("stderr"); sys.exit(7)')
        result = self.executor.execute(shlex.join([sys.executable, '-c', script]), capture=True)
        self.assertEqual(result, dict(exitCode=7, output='x' * 1000000 + 'stderr'))

    def test_pipe_stream_complete_before_command_result(self):
        lines = []
        result = self.executor.execute("printf 'one\\ntwo\\nlast'", on_line=lines.append)
        self.assertEqual(lines, ['one\n', 'two\n', 'last'])
        self.assertEqual(result, dict(exitCode=0, output=''.join(lines)))

    def test_invalid_deadline_never_launches(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            self.executor.execute('touch bad', 0)
        self.assertFalse((Path(self.executor.root) / 'bad').exists())

    def test_transfer_paths_with_spaces_and_modes(self):
        source = Path(self.output.name) / "source ' with spaces"
        target = Path(self.executor.root) / "target ' with spaces"
        source.write_bytes(b'\x00\xfffixture')
        receipt = self.executor.upload(source, target)
        self.assertEqual(receipt['path'], str(target))
        self.assertEqual(self.executor.chmod('700', target)['exitCode'], 0)
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)
        downloaded = source.with_name('download')
        self.executor.download(target, downloaded)
        self.assertEqual(source.read_bytes(), downloaded.read_bytes())

    def test_timeout_and_subsequent_command(self):
        with self.assertRaises(TimeoutError):
            self.executor.execute('exec sleep 60', 1)
        self.assertFalse(self.executor.active)
        self.assertEqual(self.executor.execute('printf recovered')['output'], 'recovered')

    def test_close_cancels_owned_tree_but_not_an_unrelated_child(self):
        unrelated = subprocess.Popen(['sleep', '60'], start_new_session=True)
        self.addCleanup(unrelated.wait)
        self.addCleanup(unrelated.kill)
        ready = queue.Queue()
        results = []
        script = 'sleep 60 & printf "ready\\n"; wait'
        thread = threading.Thread(target=lambda: results.append(
            self.executor.execute(script, 60, on_line=ready.put)))
        thread.start()
        try:
            self.assertEqual(ready.get(timeout=10), 'ready\n')
            self.executor.close()
        finally:
            self.executor.cancel()
            thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0]['exitCode'], 128 + signal.SIGKILL)
        self.assertIsNone(unrelated.poll())
        self.assertFalse(Path(self.executor.root).exists())
        with self.assertRaisesRegex(RuntimeError, 'closed'):
            self.executor.execute('true')

    def test_callback_failure_reaps_child(self):
        def failure(line):
            raise ValueError('observer failed')
        with self.assertRaisesRegex(ValueError, 'observer failed'):
            self.executor.execute('printf "ready\\n"; sleep 60', on_line=failure)
        self.assertFalse(self.executor.active)

    def test_native_signal_uses_the_shared_shell_receipt_status(self):
        result = self.executor.execute('kill -TERM $$')
        self.assertEqual(result['exitCode'], 128 + signal.SIGTERM)

    def test_independent_fork_and_explicit_retention(self):
        child = self.executor.fork()
        self.assertNotEqual(child.root, self.executor.root)
        child.close()
        self.assertFalse(Path(child.root).exists())
        self.executor.keep = True
        self.addCleanup(shutil.rmtree, self.executor.root)
        self.executor.close()
        self.assertTrue(Path(self.executor.root).exists())

    def test_cleanup_mode_zero_directories_without_following_links(self):
        outside = Path(self.output.name) / 'outside'
        outside.mkdir(mode=0o500)
        root = Path(self.executor.root)
        private = root / 'mode-zero'
        private.mkdir()
        (private / 'file').touch()
        (private / 'link').symlink_to(outside, target_is_directory=True)
        private.chmod(0)
        self.executor.close()
        self.assertFalse(root.exists())
        self.assertEqual(outside.stat().st_mode & 0o777, 0o500)

    def test_default_local_and_no_implicit_identity_switch(self):
        parser = argparse.ArgumentParser()
        with mock.patch.dict(os.environ, {}, clear=True):
            FixtureExecutor.add_argument(parser)
        self.assertEqual(parser.parse_args([]).executor, 'local')
        with self.assertRaisesRegex(ValueError, 'Unknown fixture executor'):
            FixtureExecutor.connect(self.output.name, 'root')


if __name__ == '__main__':
    unittest.main()
