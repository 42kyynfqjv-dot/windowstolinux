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

if __name__=='__main__':unittest.main()
