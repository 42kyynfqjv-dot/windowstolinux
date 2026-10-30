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
                self.assertEqual((Path(td)/'process-state.stdout').exists(), isinstance(failure, subprocess.TimeoutExpired))

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

    def test_windows_observer_is_scoped_to_owned_pid_and_creation(self):
        from unittest.mock import patch
        from launch import capture_process_state
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)
            with patch('launch.os.name','nt'), patch('launch.windows_owned_creation',return_value=987654) as identity, patch('launch.subprocess.run',return_value=subprocess.CompletedProcess([],0,b'{}',b'')) as invoke:
                r=capture_process_state(123,d,456)
            identity.assert_called_once_with(456)
            self.assertEqual(r['exit'],0)
            cmd=invoke.call_args.args[0]
            self.assertEqual(cmd[0],sys.executable)
            self.assertTrue(cmd[1].endswith('windows_wait_observer.py'))
            self.assertEqual(cmd[-2:],['123','987654'])
            self.assertEqual(invoke.call_args.kwargs['timeout'],3)

    def test_windows_identity_failure_prevents_observer(self):
        from unittest.mock import patch
        from launch import capture_process_state
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)
            with patch('launch.os.name','nt'), patch('launch.windows_owned_creation',side_effect=OSError('handle unavailable')), patch('launch.subprocess.run') as invoke:
                r=capture_process_state(123,d,None)
            invoke.assert_not_called()
            self.assertIn('handle unavailable',r['error'])

    def test_observer_timeout_retains_partial_bytes(self):
        from unittest.mock import patch
        from launch import capture_process_state
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)
            failure=subprocess.TimeoutExpired(['observer'],3,output=b'partial',stderr=b'error')
            with patch('launch.subprocess.run',side_effect=failure):
                r=capture_process_state(123,d)
            self.assertIn('TimeoutExpired',r['error'])
            self.assertEqual((d/'process-state.stdout').read_bytes(),b'partial')
            self.assertEqual((d/'process-state.stderr').read_bytes(),b'error')

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

class FailureCleanup(unittest.TestCase):
    def child(self, timeout):
        from unittest.mock import Mock
        child = Mock(pid=123)
        child.wait.side_effect = [timeout, 1]
        child.poll.side_effect = [None, None, 1]
        return child

    def test_partial_observer_disk_failure_preserves_child_timeout_and_reaps(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            primary = subprocess.TimeoutExpired(['original-child'], 15)
            child = self.child(primary)
            observer = subprocess.TimeoutExpired(['observer'], 3, output=b'partial')
            with patch('launch.platform.platform', return_value='authored-test'), patch('launch.windows_owned_creation', return_value=456), patch('launch.subprocess.Popen', return_value=child), patch('launch.subprocess.run', side_effect=observer), patch.object(Path, 'write_bytes', side_effect=OSError('disk full')):
                with self.assertRaises(subprocess.TimeoutExpired) as raised:
                    execute([sys.executable], d/'out', d/'err', d/'evidence', {}, {}, timeout=15)
            self.assertIs(raised.exception, primary)
            child.kill.assert_called_once_with()
            self.assertEqual(child.wait.call_args_list[-1].kwargs, {'timeout': 5})
            record = json.loads((d/'evidence/launch.json').read_text())
            self.assertEqual(record['exit_after_kill'], 1)
            self.assertEqual(len(record['process_state_capture']['evidence_errors']), 2)
            self.assertIn('original-child', record['failure'])

    def test_unexpected_observer_failure_preserves_child_timeout_and_reaps(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            primary = subprocess.TimeoutExpired(['original-child'], 15)
            child = self.child(primary)
            with patch('launch.subprocess.Popen', return_value=child), patch('launch.capture_process_state', side_effect=RuntimeError('unexpected observer error')):
                with self.assertRaises(subprocess.TimeoutExpired) as raised:
                    execute([sys.executable], d/'out', d/'err', d/'evidence', {}, {}, timeout=15)
            self.assertIs(raised.exception, primary)
            child.kill.assert_called_once_with()
            self.assertEqual(child.wait.call_args_list[-1].kwargs, {'timeout': 5})
            record = json.loads((d/'evidence/launch.json').read_text())
            self.assertEqual(record['diagnostic_errors'][0]['stage'], 'observer')
            self.assertEqual(record['final_poll'], 1)

    def test_timeout_and_final_save_failures_do_not_mask_primary_or_skip_cleanup(self):
        from unittest.mock import patch
        original_write = Path.write_text
        # Saves: initial, post-spawn, pre-observer, post-observer, final.
        # Test each failure plus persistent failures from the first timeout save.
        for failed_calls in ({3}, {4}, {5}, {3, 4, 5, 6}):
            with self.subTest(failed_calls=failed_calls), tempfile.TemporaryDirectory() as td:
                d = Path(td); calls = []
                primary = subprocess.TimeoutExpired(['original-child'], 15)
                child = self.child(primary)
                def write(path, *args, **kwargs):
                    calls.append(path)
                    if len(calls) in failed_calls:
                        raise OSError('evidence write failed')
                    return original_write(path, *args, **kwargs)
                with patch('launch.subprocess.Popen', return_value=child), patch('launch.capture_process_state', return_value={'exit': 0}), patch.object(Path, 'write_text', write):
                    with self.assertRaises(subprocess.TimeoutExpired) as raised:
                        execute([sys.executable], d/'out', d/'err', d/'evidence', {}, {}, timeout=15)
                self.assertIs(raised.exception, primary)
                child.kill.assert_called_once_with()
                self.assertEqual(child.wait.call_args_list[-1].kwargs, {'timeout': 5})

    def test_post_spawn_save_failure_still_cleans_owned_child(self):
        from unittest.mock import patch, Mock
        original_write = Path.write_text
        with tempfile.TemporaryDirectory() as td:
            d = Path(td); calls = []
            primary = OSError('post-spawn save failed')
            child = Mock(pid=123)
            child.poll.side_effect = [None, 1]
            child.wait.return_value = 1
            def write(path, *args, **kwargs):
                calls.append(path)
                if len(calls) == 2:
                    raise primary
                return original_write(path, *args, **kwargs)
            with patch('launch.subprocess.Popen', return_value=child), patch.object(Path, 'write_text', write):
                with self.assertRaises(OSError) as raised:
                    execute([sys.executable], d/'out', d/'err', d/'evidence', {}, {}, timeout=15)
            self.assertIs(raised.exception, primary)
            child.kill.assert_called_once_with()
            child.wait.assert_called_once_with(timeout=5)

if __name__=='__main__':unittest.main()
