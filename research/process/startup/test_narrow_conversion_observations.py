"""Protocol and independent failure-output acceptance, not API execution."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from narrow_conversion_observations import EXPECTATIONS, KIND, narrow_conversion_observations


def records():
    result = [dict(kind=KIND, arch='x86_64', initial_ansi_raw=256, oem_raw=0,
                   ansi_raw=256, restored_raw=1, acp=1252, oemcp=437,
                   export_owner_utf16=list('C:\\Windows\\System32\\KernelBase.dll'.encode('utf-16le')[::2]))]
    for case in json.loads(EXPECTATIONS.read_text())['cases']:
        row = {k: copy.deepcopy(case[k]) for k in ('label', 'utf16', 'input_count', 'flags', 'capacity', 'query_nonnull')}
        row.update(result=case['expected_return'], last_error=case['expected_error'] or 0xdeadbeef,
                   bytes=[0x5a]*(case['capacity']+4))
        if case['capacity'] and case['expected_return']:
            payload = case['expected_payload']
            row['bytes'][:len(payload)] = payload
        elif case['capacity']:
            # An independently chosen partial effect: the protocol must retain
            # it without imposing an invented atomic-failure guarantee.
            row['bytes'][0] = 0x42
        result.append(row)
    return result


class NarrowConversionObservations(unittest.TestCase):
    def check_rows(self, rows):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'original.jsonl'
            path.write_text(''.join(json.dumps(row)+'\n' for row in rows))
            return narrow_conversion_observations(path)

    def test_raw_noncanonical_bool_nonutf8_acp_and_failure_writes_preserved(self):
        self.assertEqual(len(self.check_rows(records())), 64)

    def test_missing_forged_or_corrupted_evidence_rejects(self):
        for mode in range(19):
            rows = copy.deepcopy(records())
            if mode == 0: rows.pop()
            elif mode == 1: rows.append(rows[-1])
            elif mode == 2: rows[0]['kind'] = 'native modeled result'
            elif mode == 3: rows[0]['oem_raw'] = 1
            elif mode == 4: rows[0]['ansi_raw'] = 0
            elif mode == 5: rows[0]['restored_raw'] = 0
            elif mode == 6: rows[0]['acp'] = True
            elif mode == 7: rows[0]['export_owner_utf16'][0] = 0xd800
            elif mode == 8: rows[0]['arch'] = ''
            elif mode == 9: rows[1]['input_count'] = True
            elif mode == 10: rows[1]['utf16'][0] = 66
            elif mode == 11: rows[2]['result'] = 8
            elif mode == 12: rows[3]['bytes'][0] ^= 1
            elif mode == 13: rows[8]['last_error'] = 73
            elif mode == 14: rows[8]['bytes'][-1] = 0
            elif mode == 15: rows[1]['bytes'].pop()
            elif mode == 16: rows[1]['bytes'][0] = 0
            elif mode == 17: rows[3]['bytes'][0] = True
            else: rows[0]['initial_ansi_raw'] = 1 << 31
            with self.subTest(mode=mode), self.assertRaises((ValueError, UnicodeError)):
                self.check_rows(rows)

    def test_absent_or_nonrecord_input_rejects(self):
        with self.assertRaises(ValueError): self.check_rows([None]*16)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError): narrow_conversion_observations(Path(directory)/'missing')
