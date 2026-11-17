"""An optional transport is selected explicitly, never inferred from a product."""
import os
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
from fixture_executor import FixtureExecutor


class HostIntegration(unittest.TestCase):
    def test_missing_adapter_is_explicit(self):
        with patch.dict(os.environ, {}, clear=True), tempfile.TemporaryDirectory() as output:
            for mode in ('shell', 'app'):
                with self.assertRaisesRegex(RuntimeError, 'SHROOT_TEST_ADAPTER'):
                    FixtureExecutor.connect(output, mode)

    def test_transport_receives_identity_and_connection_unchanged(self):
        host = types.ModuleType('test_host')
        host.executor = Mock()
        with patch.dict(os.environ, {'SHROOT_TEST_ADAPTER': 'test_host'}), patch.dict('sys.modules', test_host=host):
            result = FixtureExecutor.connect('/output', 'app', 'case', config='/config', server='selected')
        host.executor.assert_called_once_with('/output', 'app', 'case', config='/config', server='selected')
        self.assertIs(result, host.executor.return_value)

    def test_adapter_failure_never_falls_back_to_another_identity(self):
        with patch('fixture_executor.adapter', side_effect=ImportError('missing host')):
            with self.assertRaisesRegex(ImportError, 'missing host'):
                FixtureExecutor.connect('/output', 'shell')


if __name__ == '__main__':
    unittest.main()
