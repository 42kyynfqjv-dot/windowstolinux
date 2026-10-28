"""Evidence parser negatives, not original Windows executions."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from check_normal_wrapper import observations
from observe_stdio import CASES, summarize, write_wrapper_vectors
from test_observe_stdio import sample, encoded


class WrapperEvidenceTests(unittest.TestCase):
    def test_vector_writer_uses_canonical_bytes_without_host_text_translation(self):
        class ByteSink:
            def write_bytes(self, data):
                self.data = data
            def write_text(self, data):
                raise AssertionError('host text translation would corrupt evidence hashes')
        sink = ByteSink()
        write_wrapper_vectors(sink, ['1 2 3', '4 5 6'])
        self.assertEqual(sink.data, b'1 2 3\n4 5 6\n')

    def test_synthetic_report_cannot_be_counted_as_original_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path/'report.json').write_text(json.dumps(dict(kind='synthetic', runs=[])))
            with self.assertRaisesRegex(ValueError, 'not synthetic'):
                observations(path)

    def test_summary_and_raw_hash_must_agree(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            records = []
            for label in [*CASES, 'cleanup-failure']:
                rows, plan = sample('baseline' if label == 'cleanup-failure' else label)
                if label == 'cleanup-failure':
                    rows = [dict(kind='summary', success=False, cleanup_ok=True, child_exited=True,
                                 child_exit=125, interval_complete=False, breakpoints_restored=True, events=8, hits=1)]
                raw = encoded(rows)
                (path/label).mkdir()
                (path/label/'observer.stdout').write_bytes(raw)
                record = dict(label=label, observer_stdout_sha256=hashlib.sha256(raw).hexdigest())
                if label != 'cleanup-failure':
                    record['observed'] = summarize(rows, label, plan)
                records.append(record)
            report = dict(plan, kind='separately instrumented original CRT observations; no whole-PE translations', runs=records)
            file = path/'report.json'
            file.write_text(json.dumps(report))
            self.assertEqual(len(observations(path)[1]), 5)
            records[0]['observed']['wrapper']['return_eax'] += 1
            file.write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, 'summary differs'):
                observations(path)
            records[0]['observer_stdout_sha256'] = '0'*64
            file.write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, 'hash changed'):
                observations(path)


if __name__ == '__main__':
    unittest.main()
