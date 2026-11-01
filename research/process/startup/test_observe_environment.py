"""Synthetic protocol cases, not Windows observations or real environment data."""
import json
import unittest
from observe_environment import validate


class EnvironmentProtocol(unittest.TestCase):
    def rows(self):
        units = sum(len(s.encode('utf-16le'))//2+1 for s in ['W2L_ALPHA=one', 'W2L_EMPTY=', 'W2L_UNICODE=雪😀'])+1
        return [dict(case=label, entries=count, units=size, distinct_live=True,
                     stable_after_mutation=True, free_first=True, free_second=True)
                for label, count, size in [('synthetic', 3, units), ('empty', 0, 2)]]

    def raw(self, rows):
        return ('\r\n'.join(json.dumps(r) for r in rows)+'\r\n').encode()

    def test_expected_controlled_layout(self):
        self.assertEqual(len(validate(self.raw(self.rows()))), 64)

    def test_partial_failed_or_wrong_layout_cannot_pass(self):
        for key, value in [('free_first', False), ('free_second', False),
                           ('stable_after_mutation', False), ('distinct_live', False),
                           ('units', 0), ('entries', True), ('case', 'other')]:
            rows = self.rows()
            rows[0][key] = value
            with self.assertRaises(ValueError):
                validate(self.raw(rows))
        with self.assertRaises(ValueError):
            validate(self.raw(self.rows()[:1]))


if __name__ == '__main__':
    unittest.main()
