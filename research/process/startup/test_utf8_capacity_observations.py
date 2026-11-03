"""Synthetic protocol tests only; these are not Windows API executions."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from utf8_capacity_observations import KIND, schedule, utf8_capacity_observations


def records():
    rows = [dict(kind=KIND, arch='x86_64')]
    for v, flags, cap in schedule():
        success = (not v['invalid_utf16'] or flags == 0) and (cap == 0 or cap >= len(v['payload']))
        row = dict(label=v['label'], utf16=v['utf16'].copy(), input_count=v['input_count'], flags=flags, capacity=cap,
                   result=len(v['payload']) if success else 0, last_error=73 if success else 122, bytes=[0x5a]*(cap+4))
        if success and cap:
            row['bytes'][:len(v['payload'])] = v['payload']
        elif cap:
            row['bytes'][0] = 0x42  # Deliberate observable failure mutation.
        rows.append(row)
    return rows


class CapacityObservations(unittest.TestCase):
    def check_rows(self, rows):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)/'original.jsonl'
            p.write_text(''.join(json.dumps(row)+'\n' for row in rows))
            return utf8_capacity_observations(p)

    def test_complete_records_and_unconstrained_failure_bytes(self):
        self.assertEqual(len(schedule()), 158)
        self.assertEqual(len(self.check_rows(records())), 64)

    def test_missing_forged_or_mutated_effects_reject(self):
        for mode in range(11):
            rows = copy.deepcopy(records())
            if mode == 0: rows.pop()
            elif mode == 1: rows[0]['kind'] = 'modeled API'
            elif mode == 2: rows[1]['flags'] = True
            elif mode == 3: rows[1]['utf16'][0] = 66
            elif mode == 4: rows[1]['result'] = 0
            elif mode == 5: rows[2]['last_error'] = 73
            elif mode == 6: rows[2]['bytes'][-1] = 0
            elif mode == 7: rows[4]['bytes'][0] ^= 1
            elif mode == 8: rows[-1]['bytes'].pop()
            elif mode == 9: rows[1]['bytes'][0] = True
            else: rows[1]['last_error'] = -1
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.check_rows(rows)

    def test_nonrecord_input_rejects(self):
        with self.assertRaises(ValueError): self.check_rows([None]*159)
