"""Independent malformed evidence gates; no original executable is run here."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_stdio


class StdioGateTests(unittest.TestCase):
    def test_tampered_artifact_rejects_before_compiler_or_output_creation(self):
        for key, filename in [('pe_sha256', 'unwind.exe'),
                              ('object_sha256', 'unwind.obj'),
                              ('source_sha256', 'unwind_probe.c')]:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                original, observed, output = root / 'original', root / 'observed', root / 'output'
                original.mkdir()
                observed.mkdir()
                identity = {}
                for field, name in [('pe_sha256', 'unwind.exe'),
                                    ('object_sha256', 'unwind.obj'),
                                    ('source_sha256', 'unwind_probe.c')]:
                    raw = ('retained-' + name).encode()
                    (original / name).write_bytes(raw)
                    identity[field] = check_stdio.sha(raw)
                for path in [original / 'report.json', observed / 'plan.json', observed / 'report.json']:
                    path.write_text(json.dumps(identity))
                (original / filename).write_bytes(b'changed after observation')
                with patch.object(check_stdio, 'command') as compiler:
                    with self.assertRaisesRegex(ValueError, 'artifact identity: ' + key):
                        check_stdio.run(original, observed, output)
                    compiler.assert_not_called()
                self.assertFalse(output.exists())

    def test_cross_host_requires_windows_linux_and_identical_actual_results(self):
        record = dict(system='Windows', pe_sha256='pe', object_sha256='obj', source_sha256='c',
                      frozen_expectations_sha256='expectations', emitted_rust_sha256='rust',
                      native_runner_source_sha256='runner', counts=dict(whole_pe_translation_pairs=0),
                      results=[dict(id='binary', expected=[0, 6, 1], actual=[0, 6, 1])],
                      supplemental_results=[dict(id='over-limit', rejected_entries=2, backend_calls=0)])
        linux = copy.deepcopy(record)
        linux['system'] = 'Linux'
        check_stdio.require_cross_host(record, linux)
        for system in ['Linux', 'Darwin', None]:
            prior = copy.deepcopy(record)
            prior['system'] = system
            with self.subTest(system=system), self.assertRaises(ValueError):
                check_stdio.require_cross_host(prior, linux)
        for field in ['pe_sha256', 'emitted_rust_sha256', 'native_runner_source_sha256', 'counts', 'results', 'supplemental_results']:
            changed = copy.deepcopy(record)
            changed[field] = None
            with self.subTest(field=field), self.assertRaises(ValueError):
                check_stdio.require_cross_host(changed, linux)


if __name__ == '__main__':
    unittest.main()
