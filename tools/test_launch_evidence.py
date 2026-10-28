"""Real child processes verify success and timeout evidence without PE assumptions."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
spec = importlib.util.spec_from_file_location('launch', Path(__file__).resolve().parents[1]/'corpus/launch.py')
launch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launch)

class LaunchEvidence(unittest.TestCase):
    def test_success_and_timeout_preserve_bytes_identity_and_state(self):
        for source, timeout in [("print('ready', flush=True)", 15),
                                ("import time; print('ready', flush=True); time.sleep(30)", .5)]:
            with tempfile.TemporaryDirectory() as d:
                root=Path(d); command=[sys.executable, '-c', source]
                if timeout < 1:
                    with self.assertRaises(subprocess.TimeoutExpired):
                        launch.execute(command,root/'out',root/'err',root/'evidence',{}, {}, timeout)
                else:
                    self.assertEqual(launch.execute(command,root/'out',root/'err',root/'evidence',{}, {}, timeout).returncode,0)
                r=json.loads((root/'evidence/launch.json').read_text())
                self.assertEqual(r['timeout'], timeout < 1)
                self.assertEqual((root/'evidence/program.bin').read_bytes(),Path(sys.executable).read_bytes())
                self.assertEqual((root/'evidence/stdout').read_bytes(), b'ready\n')
                self.assertIn('pid',r)
                self.assertIn('spawn_seconds',r)
                self.assertEqual(r['final_poll'] is None,False)
                if timeout < 1:
                    self.assertIsNone(r['poll_at_timeout'])
                    self.assertEqual(r['stage'],'failed')

    def test_complete_expected_output_does_not_turn_live_child_timeout_into_success(self):
        # Reproduce the observed max boundary without executing a foreign PE:
        # complete expected output followed by a still-live owned process.
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            expected = b'A' * 64
            command = [sys.executable, '-c',
                       "import sys,time; sys.stdout.buffer.write(b'A'*64); sys.stdout.buffer.flush(); time.sleep(30)"]
            with self.assertRaises(subprocess.TimeoutExpired):
                launch.execute(command, root/'out', root/'err', root/'evidence',
                               {}, {'stdout_hex': expected.hex(), 'exit': 0}, .5)
            record = json.loads((root/'evidence/launch.json').read_text())
            self.assertEqual(bytes.fromhex(record['stdout_hex']), expected)
            self.assertEqual(record['stderr_hex'], '')
            self.assertTrue(record['timeout'])
            self.assertIsNone(record['poll_at_timeout'])
            self.assertEqual(record['stage'], 'failed')
            self.assertIn('TimeoutExpired', record['failure'])
            self.assertIsNotNone(record['final_poll'])
            self.assertNotIn('exit', record)
