import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from check_projection_boundary import run_owned

class TimingEvidenceTests(unittest.TestCase):
    def test_timeout_preserves_partial_case_and_remains_failure(self):
        def failed(command, **options):
            self.assertEqual(options['timeout'], 15)
            self.assertTrue(options['check'])
            raise subprocess.TimeoutExpired(command, 15, output=b'', stderr=b'owned-start 183\n')
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)
            with self.assertRaises(subprocess.TimeoutExpired):run_owned(out/'probe',out,failed)
            self.assertEqual((out/'owned.stderr').read_bytes(), b'owned-start 183\n')
            self.assertEqual(json.loads((out/'owned-timing.json').read_text())['status'],'timeout')

    def test_success_requires_every_case_and_rejects_noise(self):
        rows=''.join(f'owned-start {i}\nowned-end {i} 100\n' for i in range(202)).encode()
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)
            run_owned(out/'probe',out,lambda cmd,**kw:subprocess.CompletedProcess(cmd,0,b'',rows))
            self.assertEqual(len(json.loads((out/'owned-timing.json').read_text())['case_microseconds']),202)
            for bad in [rows+b'noise\n',rows.replace(b'owned-start 1\n',b'owned-start 0\n')]:
                with self.assertRaises(ValueError):run_owned(out/'probe',out,lambda cmd,**kw:subprocess.CompletedProcess(cmd,0,b'',bad))
