import struct,unittest
from check_runtime import normalized
class Identity(unittest.TestCase):
    def image(self):
        b=bytearray(0x2200);b[:2]=b'MZ';struct.pack_into('<I',b,60,0x80);b[0x80:0x84]=b'PE\0\0'
        struct.pack_into('<HH',b,0x84,0x14c,1);struct.pack_into('<H',b,0x94,224);struct.pack_into('<H',b,0x98,0x10b)
        struct.pack_into('<I',b,0xb4,0x400000);struct.pack_into('<I',b,0xd0,0x3000)
        struct.pack_into('<II',b,0x120,0x1800,12);struct.pack_into('<IIII',b,0x180,0x2000,0x1000,0x2000,0x200)
        struct.pack_into('<I',b,0x300,0x401234);struct.pack_into('<IIHH',b,0xa00,0x1000,12,0x3100,0)
        return b
    def test_independent_highlow_and_other_base(self):
        b=self.image();self.assertEqual(normalized(b,0x1100,4,0x500000),(bytes.fromhex('34125000'),[0x1100],0x3000))
        self.assertEqual(normalized(b,0x1100,4,0x400000)[0],bytes.fromhex('34124000'))
    def test_partial_duplicate_unsupported_unbacked(self):
        for word in [0x3102,0x2100]:
            b=self.image();struct.pack_into('<H',b,0xa08,word)
            with self.assertRaises(AssertionError):normalized(b,0x1100,4,0x500000)
        b=self.image();struct.pack_into('<H',b,0xa0a,0x3100)
        with self.assertRaises(AssertionError):normalized(b,0x1100,4,0x500000)
        with self.assertRaises(AssertionError):normalized(self.image(),0x2fff,4,0x500000)
if __name__=='__main__':unittest.main()
