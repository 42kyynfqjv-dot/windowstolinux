import hashlib
import json
from pathlib import Path
import struct
import unittest
import observe_filter_exchange as subject


class ExchangeExpectations(unittest.TestCase):
    def test_frozen_identities_are_complete_and_reject_changed_or_missing_words(self):
        here = Path(__file__).resolve().parent
        expected = json.loads((here / 'filter-exchange-expectations.json').read_text())
        self.assertEqual(expected['checks'], [1] * 6)
        self.assertEqual(expected['magic'], 0x31524655)
        frozen = json.loads((here / 'filter-exchange-frozen.json').read_text())
        for name, digest in frozen['sources'].items():
            self.assertEqual(hashlib.sha256((here / name).read_bytes()).hexdigest(), digest)
        words = [expected['magic'], *expected['checks']]
        data = struct.pack('<7I', *words)
        self.assertEqual(subject.validate(data, expected), 6)
        for i in range(len(data)):
            changed = bytearray(data)
            changed[i] ^= 1
            with self.assertRaises(ValueError):
                subject.validate(changed, expected)
        for changed in [data[:-1], data + b'\x00', b'']:
            with self.assertRaises(ValueError):
                subject.validate(changed, expected)


if __name__ == '__main__':
    unittest.main()
