"""Protocol-only synthetic rows are not Windows execution evidence."""
import json
import unittest
from observe_slist import KIND, validate


class SListProtocol(unittest.TestCase):
    def records(self):
        rows = [dict(kind=KIND, pointer_bytes=4, header_bytes=8, compiler=194435000)]
        for i in range(12):
            p, c = divmod(i, 3)
            at = 16+8*c
            before = [0]*8 if p == 0 else [255]*8 if p == 1 else [165]*8 if p == 2 else list(range(at, at+8))
            rows.append(dict(case=i, pattern=p, offset=at, initial=before, initialized=[3, 1, 4, 1, 5, 9, 2, 6], after_empty_pop=[2]*8, depth=0, empty_pop_null=True, guards_unchanged=True))
        return rows

    def test_private_bytes_are_observations(self):
        validate('\n'.join(map(json.dumps, self.records())).encode())

    def test_input_logical_state_guards_and_types_are_checked(self):
        for mode in range(11):
            rows = self.records()
            if mode == 0: rows.pop()
            elif mode == 1: rows[0]['pointer_bytes'] = 8
            elif mode == 2: rows[0]['header_bytes'] = 16
            elif mode == 3: rows[1]['case'] = False
            elif mode == 4: rows[1]['initial'][0] = False
            elif mode == 5: rows[1]['depth'] = 1
            elif mode == 6: rows[1]['empty_pop_null'] = False
            elif mode == 7: rows[1]['guards_unchanged'] = False
            elif mode == 8: rows[1]['initialized'].pop()
            elif mode == 9: rows[1]['offset'] += 8
            else: rows[1]['initialized'][0] = 256
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                validate('\n'.join(map(json.dumps, rows)).encode())
