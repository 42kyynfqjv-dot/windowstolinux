import unittest
from protect_conformance import frozen, validate


class ProtectEvidence(unittest.TestCase):
    def test_independent_expected_results_and_mutants(self):
        for mode, expected in enumerate(frozen()['expected']):
            row = dict(mode=mode, old=0x12345678, last_error=0)
            row.update(expected)
            row['pages'] = [987 if x is None else x for x in row['pages']]
            self.assertEqual(validate(row), expected)
            for key, value in [('ok', not row['ok']), ('pages', [4, 4]), ('mode', True), ('states', [8192]*3)]:
                with self.assertRaises(ValueError):
                    validate(dict(row, **{key: value}))
            if row['ok']:
                with self.assertRaises(ValueError):
                    validate(dict(row, old=7))
