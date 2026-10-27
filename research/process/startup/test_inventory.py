import hashlib
import struct
import unittest
from inventory import inventory


class Evidence(unittest.TestCase):
    def sample(self):
        b = bytearray(256)
        b[:2] = b'MZ'
        struct.pack_into('<I', b, 60, 64)
        b[64:68] = b'PE\0\0'
        struct.pack_into('<H', b, 68, 0x14c)
        struct.pack_into('<H', b, 88, 0x10b)
        struct.pack_into('<I', b, 104, 0x1234)
        struct.pack_into('<I', b, 116, 0x400000)
        return bytes(b)

    def test_identity_entry_and_no_authority(self):
        b = self.sample()
        r = inventory(b, '  00401234: C3 ret', hashlib.sha256(b).hexdigest())
        self.assertEqual(r['entry_rva'], '0x1234')
        self.assertFalse(r['emission_allowed'])
        self.assertEqual(r['excerpts'][0]['va'], '0x401234')
        with self.assertRaises(ValueError):
            inventory(b, '', '0'*64)

    def test_missing_ambiguous_and_truncated(self):
        b = self.sample()
        h = hashlib.sha256(b).hexdigest()
        self.assertTrue(inventory(b, '', h)['excerpts'][0]['missing'])
        with self.assertRaises(ValueError):
            inventory(b, '00401234: C3 ret\n00401234: C3 ret', h)
        with self.assertRaises(struct.error):
            inventory(b'', '', hashlib.sha256(b'').hexdigest())

    def test_relative_target_ignores_symbol_and_adjacent_thunks(self):
        b = self.sample()
        text = '00401234: E9 07 00 00 00     jmp _symbol\n00401239: E9 FF FF FF FF     jmp unrelated\n00401240: C3                 ret'
        r = inventory(b, text, hashlib.sha256(b).hexdigest())
        self.assertEqual([x['va'] for x in r['excerpts']], ['0x401234', '0x401240'])
        self.assertEqual(len(r['excerpts'][0]['lines']), 1)
