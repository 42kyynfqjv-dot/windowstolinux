"""Independent identity/failure gates plus an owned-child Windows API smoke test."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock
from windows_wait_observer import observe


class IdentityAndFailureGates(unittest.TestCase):
    def backend(self, **changes):
        api = Mock()
        api.identity.return_value = dict(pid=123, creation_time=456, alive=True, **changes)
        api.modules.return_value = [{'name': 'authored.dll', 'base': 4096, 'size': 1024}]
        api.threads.return_value = [{'tid': 789, 'nodes': [{'object_type': 8, 'object_status': 2}]}]
        return api

    def test_pid_or_creation_mismatch_does_not_inspect_any_state(self):
        for pid, creation in [(124, 456), (123, 457)]:
            api = self.backend()
            result = observe(api, pid, creation)
            self.assertIn('identity mismatch', result['error'])
            api.modules.assert_not_called()
            api.threads.assert_not_called()

    def test_exited_owned_process_does_not_inspect_any_state(self):
        api = self.backend()
        api.identity.return_value['alive'] = False
        self.assertIn('exited', observe(api, 123, 456)['error'])
        api.modules.assert_not_called()
        api.threads.assert_not_called()

    def test_api_errors_preserve_identity_and_other_observations(self):
        api = self.backend()
        error = OSError('wait-chain unavailable'); error.winerror = 5
        api.threads.side_effect = error
        stages = []
        result = observe(api, 123, 456, stages.append)
        self.assertTrue(result['identity_verified'])
        self.assertEqual(result['threads']['winerror'], 5)
        self.assertEqual(result['modules'][0]['base'], 4096)
        self.assertEqual([x['stage'] for x in stages], ['identity', 'modules', 'threads'])

    def test_identity_query_failure_cannot_fall_through(self):
        api = self.backend(); api.identity.side_effect = OSError('query failed')
        with self.assertRaises(OSError):
            observe(api, 123, 456)
        api.modules.assert_not_called()
        api.threads.assert_not_called()

    def test_non_windows_cli_reports_platform_limit(self):
        if os.name == 'nt':
            self.skipTest('non-Windows platform check')
        result = subprocess.run([sys.executable, str(Path(__file__).with_name('windows_wait_observer.py')), '123', '456'], capture_output=True, timeout=3, check=True)
        self.assertIn('unavailable on this platform', json.loads(result.stdout)['error'])


@unittest.skipUnless(os.name == 'nt', 'requires actual Windows APIs')
class WindowsOwnedChild(unittest.TestCase):
    def test_real_owned_child_identity_wait_chain_and_module_layout(self):
        import ctypes
        from launch import windows_owned_creation
        from windows_wait_observer import WindowsAPI
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        try:
            identity = windows_owned_creation(child._handle)
            # Literal SDK layout expectations catch ABI padding/width mistakes.
            api = WindowsAPI(child.pid)
            try:
                self.assertEqual(ctypes.sizeof(api.Thread), 28)
                self.assertEqual(ctypes.sizeof(api.Node), 280)
                self.assertEqual(ctypes.sizeof(api.Module), 1080 if ctypes.sizeof(ctypes.c_void_p) == 8 else 1064)
            finally:
                api.finish()
            result = subprocess.run([sys.executable, str(Path(__file__).with_name('windows_wait_observer.py')), str(child.pid), str(identity)], capture_output=True, timeout=3, check=True)
            record = json.loads(result.stdout.splitlines()[-1])
            self.assertTrue(record['identity_verified'], record)
            self.assertEqual({k: record['identity'][k] for k in ('pid','creation_time','alive')}, {'pid': child.pid, 'creation_time': identity, 'alive': True})
            self.assertGreaterEqual(record['identity']['cpu_seconds'],0)
            self.assertGreater(record['identity']['handles'],0)
            for key in ('modules', 'threads'):
                value = record[key]
                if isinstance(value, dict):
                    # Snapshot BAD_LENGTH is a documented transient; no retry.
                    # Invalid structure arguments still fail this actual API test.
                    allowed = (5, 50, 120) if key == 'threads' else (5, 299)
                    if value.get('operation') == 'CreateToolhelp32Snapshot':
                        allowed += (24,)
                    self.assertIn(value.get('winerror'), allowed, value)
                else:
                    self.assertGreater(len(value), 0, value)
            if isinstance(record['modules'], list):
                self.assertTrue(any(x['name'].lower().startswith('python') for x in record['modules']))
                self.assertTrue(all(x['base'] > 0 and x['size'] > 0 for x in record['modules']))
            if isinstance(record['threads'], list):
                for thread in record['threads']:
                    if 'error' in thread:
                        self.assertIn(thread.get('winerror'), (5, 50, 120), thread)
                    else:
                        self.assertGreater(len(thread['nodes']), 0, thread)
                        self.assertTrue(all(1 <= n['object_type'] <= 14 for n in thread['nodes']))
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
