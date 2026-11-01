"""Independent raw API evidence protocol cases, not Windows executions."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from check_normal_wrapper import image_name_observations, sha


def records():
    raw = '/tmp/建😀.exe'.encode('utf-16le')
    units = [int.from_bytes(raw[n:n+2], 'little') for n in range(0, len(raw), 2)]
    length = len(units)
    result = [dict(kind='original Windows GetModuleFileNameW API component; no PE translation',
                   arch='x86_64', baseline_utf16=units)]
    for count in [1, 2, length, length+1, length+2, 261]:
        truncated = length >= count
        output = [0x5a5a] * (count+3)
        payload = units[:count-1] if truncated else units
        output[:len(payload)] = payload
        output[len(payload)] = 0
        result.append(dict(count=count, result=count if truncated else length,
                           last_error=122 if truncated else 0xdeadbeef, units=output))
    return result


class ImageNameObservations(unittest.TestCase):
    def check_rows(self, rows):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'original.jsonl'
            raw = ''.join(json.dumps(row)+'\n' for row in rows).encode()
            path.write_bytes(raw)
            result = image_name_observations(path)
            self.assertEqual(result, sha(raw))

    def test_complete_raw_effects_accept_arbitrary_success_last_error(self):
        self.check_rows(records())

    def test_missing_or_mutated_effects_cannot_count_as_observations(self):
        for mode in range(16):
            rows = copy.deepcopy(records())
            if mode == 0: rows.pop()
            elif mode == 1: rows.append(rows[-1])
            elif mode == 2: rows[0]['kind'] = 'scripted native result'
            elif mode == 3: rows[0]['baseline_utf16'] = []
            elif mode == 4: rows[0]['baseline_utf16'][0] = 0
            elif mode == 5: rows[0]['baseline_utf16'][0] = 0xd800
            elif mode == 6: del rows[1]['units']
            elif mode == 7: rows[1]['count'] = True
            elif mode == 8: rows[1]['result'] = 0
            elif mode == 9: rows[1]['last_error'] = 73
            elif mode == 10: rows[-1]['units'][-1] = 0
            elif mode == 11: rows[-1]['units'].pop()
            elif mode == 12: rows[2]['units'][0] ^= 1
            elif mode == 13: del rows[0]['arch']
            elif mode == 14: rows[1]['last_error'] = -1
            else: rows[1] = {'count': 1}
            with self.subTest(mode=mode), self.assertRaises((ValueError, UnicodeError)):
                self.check_rows(rows)

    def test_non_record_or_non_json_input_rejects(self):
        with self.assertRaises(ValueError): self.check_rows([None]*7)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'bad.jsonl'
            path.write_text('not an API observation\n')
            with self.assertRaises(ValueError): image_name_observations(path)
