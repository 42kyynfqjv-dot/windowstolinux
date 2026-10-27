"""Actual bounded child failure must retain evidence and still raise."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from launch import execute

class LaunchEvidence(unittest.TestCase):
    def test_timeout_remains_failure_and_retains_owned_process_state(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)
            with self.assertRaises(subprocess.TimeoutExpired):
                execute([sys.executable,'-c','import time; time.sleep(30)'],d/'out',d/'err',d/'evidence',{'case':'authored-test'}, {},timeout=0.2)
            r=json.loads((d/'evidence/launch.json').read_text())
            self.assertTrue(r['timeout'])
            self.assertEqual(r['timeout_seconds'],0.2)
            self.assertIn('process_state_capture',r)
            self.assertIn('exit_after_kill',r)
            self.assertLess(r['process_state_capture']['seconds'],5)
            self.assertEqual(r['stage'],'failed')
            self.assertTrue((d/'evidence/program.bin').exists())


class DiagnosticFailures(unittest.TestCase):
    def test_unavailable_command_and_diagnostic_timeout_are_recorded(self):
        from unittest.mock import patch
        from launch import capture_process_state
        for failure in [FileNotFoundError('diagnostic unavailable'),
                        subprocess.TimeoutExpired(['diagnostic'],3)]:
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as td:
                with patch('launch.subprocess.run',side_effect=failure) as invoke:
                    r=capture_process_state(123,Path(td))
                self.assertIn(type(failure).__name__,r['error'])
                self.assertEqual(invoke.call_args.kwargs['timeout'],3)
                self.assertFalse((Path(td)/'process-state.stdout').exists())

    def test_nonzero_exit_preserves_diagnostics_including_exited_child(self):
        from unittest.mock import patch
        from launch import capture_process_state
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)
            with patch('launch.subprocess.run',return_value=subprocess.CompletedProcess([],1,b'',b'process already exited')):
                r=capture_process_state(123,d)
            self.assertEqual(r['exit'],1)
            self.assertEqual((d/'process-state.stderr').read_bytes(),b'process already exited')
            self.assertEqual((d/'process-state.stdout').read_bytes(),b'')

    def test_windows_observer_is_scoped_to_owned_pid(self):
        from unittest.mock import patch
        from launch import capture_process_state
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)
            with patch('launch.os.name','nt'),patch('launch.subprocess.run',return_value=subprocess.CompletedProcess([],0,b'{}',b'')) as invoke:
                r=capture_process_state(123,d)
            self.assertEqual(r['exit'],0)
            cmd=invoke.call_args.args[0]
            self.assertEqual(cmd[0],'powershell.exe')
            self.assertIn('Get-Process -Id 123 ',cmd[-1])
            self.assertNotIn('Stop-Process',cmd[-1])

    def test_diagnostic_error_cannot_replace_primary_timeout_or_output(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)
            with patch('launch.capture_process_state',return_value={'error':'diagnostic unavailable','seconds':0}):
                with self.assertRaises(subprocess.TimeoutExpired):
                    execute([sys.executable,'-c',"import time; print('ready',flush=True); time.sleep(30)"],d/'out',d/'err',d/'evidence',{'case':'independent-child'},{},timeout=0.5)
            r=json.loads((d/'evidence/launch.json').read_text())
            self.assertTrue(r['timeout'])
            self.assertEqual(bytes.fromhex(r['stdout_hex']).strip(),b'ready')
            self.assertEqual(r['stderr_hex'],'')
            self.assertTrue(r['failure'].startswith('TimeoutExpired:'))
            self.assertEqual(r['process_state_capture']['error'],'diagnostic unavailable')
            self.assertIn('exit_after_kill',r)
            import hashlib
            self.assertEqual(hashlib.sha256((d/'evidence/program.bin').read_bytes()).hexdigest(),r['executed_sha256'])

    def test_child_exit_during_diagnostics_preserves_timeout_without_kill(self):
        from unittest.mock import patch, Mock
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)
            child=Mock(pid=123)
            child.wait.side_effect=[subprocess.TimeoutExpired(['child'],15),0]
            child.poll.return_value=0
            with patch('launch.platform.platform',return_value='authored-test'), patch('launch.subprocess.Popen',return_value=child), patch('launch.capture_process_state',return_value={'exit':1,'seconds':0}):
                with self.assertRaises(subprocess.TimeoutExpired):
                    execute([sys.executable],d/'out',d/'err',d/'evidence',{}, {},timeout=15)
            child.kill.assert_not_called()
            r=json.loads((d/'evidence/launch.json').read_text())
            self.assertTrue(r['timeout'])
            self.assertEqual(r['exit_during_diagnostics'],0)
            self.assertEqual(r['stage'],'failed')
            self.assertNotIn('exit_after_kill',r)

if __name__=='__main__':unittest.main()
