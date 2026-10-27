"""Independently authored metadata, not a copied Windows module."""
import struct
import unittest
from module_identity import identify


def fixture():
    data = bytearray(1024)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 128)
    data[128:132] = b'PE\0\0'
    struct.pack_into('<HHI', data, 132, 0x14c, 1, 77)
    struct.pack_into('<H', data, 148, 224)
    struct.pack_into('<H', data, 152, 0x10b)
    struct.pack_into('<I', data, 208, 0x3000)
    struct.pack_into('<I', data, 244, 16)
    struct.pack_into('<II', data, 248, 0x1000, 128)
    struct.pack_into('<IIII', data, 384, 512, 0x1000, 512, 512)
    struct.pack_into('<IIIII', data, 532, 1, 1, 0x1040, 0x1044, 0x1048)
    struct.pack_into('<IIH', data, 576, 0x1200, 0x1050, 0)
    data[592:600] = b'Handler\0'
    return data


class Identity(unittest.TestCase):
    def test_exact_export_not_nearest_symbol(self):
        data = fixture()
        self.assertEqual(identify(data, 0x1200, 0x14c, 77, 0x3000)['exact_named_exports'], ['Handler'])
        self.assertEqual(identify(data, 0x1201, 0x14c, 77, 0x3000)['exact_named_exports'], [])
        struct.pack_into('<I', data, 576, 0x1050)
        self.assertEqual(identify(data, 0x1050, 0x14c, 77, 0x3000)['exact_named_exports'], [])

    def test_mismatched_loaded_identity_rejected(self):
        for machine, stamp, size in [(0x8664,77,0x3000),(0x14c,78,0x3000),(0x14c,77,0x4000)]:
            with self.assertRaises(ValueError):
                identify(fixture(), 0x1200, machine, stamp, size)

    def test_truncated_or_invalid_export_mapping_rejected(self):
        data = fixture()
        for end in (0, 63, 151, 399, 550, 590):
            with self.assertRaises(ValueError):
                identify(data[:end], 0x1200, 0x14c, 77, 0x3000)
        struct.pack_into('<H', data, 584, 1)
        with self.assertRaises(ValueError):
            identify(data, 0x1200, 0x14c, 77, 0x3000)


if __name__ == '__main__':
    unittest.main()
