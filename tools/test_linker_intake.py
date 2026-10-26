"""Independently laid out bytes and literal expectations for the design model.

This is not an executable fixture generator and imports no production code.
"""
import struct
import unittest

from linker_intake import Candidate, Rejected, end32


def put(blob, offset, fmt, *values):
    struct.pack_into(fmt, blob, offset, *values)


def image():
    b = bytearray(0xa00)
    b[:2] = b'MZ'
    put(b, 0x3c, '<I', 0x80)
    b[0x80:0x84] = b'PE\0\0'
    put(b, 0x84, '<HHIIIHH', 0x14c, 3, 0, 0, 0, 0xe0, 0x102)
    put(b, 0x98, '<H', 0x10b)
    put(b, 0x9c, '<IIIIII', 0x200, 0x400, 0, 0x1000, 0x1000, 0x2000)
    put(b, 0xb4, '<III', 0x400000, 0x1000, 0x200)
    put(b, 0xd0, '<II', 0x4000, 0x400)
    put(b, 0xdc, '<HHIIII', 3, 0x8540, 0x100000, 0x1000, 0x100000, 0x1000)
    put(b, 0xf4, '<I', 16)
    for index, rva, size in [(1, 0x2080, 40), (5, 0x3000, 12), (6, 0x2010, 28), (12, 0x2000, 8)]:
        put(b, 0xf8 + 8 * index, '<II', rva, size)
    for i, (vs, va, raw, flags) in enumerate([
            (0x10, 0x1000, 0x400, 0x60000020),
            (0x100, 0x2000, 0x600, 0x40000040),
            (12, 0x3000, 0x800, 0x42000040)]):
        put(b, 0x178 + 40 * i + 8, '<IIIIIIHHI', vs, va, 0x200, raw, 0, 0, 0, 0, flags)
    # Literal address fields at 1001 and 1007. No production assembler/decoder.
    b[0x400:0x40c] = bytes.fromhex('68 60 20 40 00 ff 15 00 20 40 00 c3')
    put(b, 0x600, '<II', 0x20c0, 0)
    put(b, 0x610, '<IIHHIIII', 0, 0, 0, 0, 13, 8, 0x2040, 0x640)
    b[0x640:0x648] = b'opaque!!'
    b[0x660:0x665] = b'Hello'
    put(b, 0x680, '<IIIII', 0x20b0, 0, 0, 0x20d0, 0x2000)
    put(b, 0x6b0, '<II', 0x20c0, 0)
    b[0x6c0:0x6c9] = b'\0\0_write\0'
    b[0x6d0:0x6db] = b'msvcrt.dll\0'
    put(b, 0x800, '<IIHH', 0x1000, 12, 0x3001, 0x3007)
    return b


class LinkerDesign(unittest.TestCase):
    def reject_mutation(self, offset, fmt, value, message):
        b = image()
        put(b, offset, fmt, value)
        with self.assertRaisesRegex(Rejected, message):
            Candidate(b)

    def test_literal_mapping_import_and_relocation_expectations(self):
        original = image()
        p = Candidate(original)
        self.assertEqual(p.location(0x2060, 5, p.DATA), 0x660)
        self.assertEqual(p.immutable(0x2060, 5), b'Hello')
        self.assertEqual([(x.site, x.rva) for x in p.pointers], [(0x1001, 0x2060), (0x1007, 0x2000)])
        self.assertEqual(p.bind([(0x1001, 'immutable-buffer', 5), (0x1007, 'import-call', 4)]),
                         [('immutable-buffer', 0x2060, 5), ('import-call', 0x2000, 4)])
        self.assertEqual(p.report(), Candidate(original).report())
        self.assertEqual(original, image())

    def test_rebase_up_down_and_nonwrapping_limits(self):
        p = Candidate(image())
        # Independent literals, including negative relocation delta.
        for base, expected in [(0x400000, [0x402060, 0x402000]),
                               (0x10000, [0x12060, 0x12000]),
                               (0x10000000, [0x10002060, 0x10002000]),
                               (0xffff0000, [0xffff2060, 0xffff2000])]:
            self.assertEqual([v for _, v in p.rebase_words(base)], expected)
        for base in (0, 1, 0x100000000, -0x10000):
            with self.subTest(base=base), self.assertRaises(Rejected):
                p.rebase_words(base)
        with self.assertRaisesRegex(Rejected, 'overflow'):
            end32(0xfffffff0, 16)
        self.assertEqual(end32(0xffffffef, 16), 0xffffffff)

    def test_whole_access_excludes_padding_headers_gaps_and_tail(self):
        p = Candidate(image())
        self.assertEqual(p.immutable(0x20ff, 1), b'\0')
        for rva, size in [(0x20ff, 2), (0x2100, 1), (0x200, 1), (0x1800, 1),
                          (0x1000, 4), (0x3000, 1), (0xfffffff0, 32), (0x2060, 0)]:
            with self.subTest(rva=rva, size=size), self.assertRaises(Rejected):
                p.immutable(rva, size)
        self.reject_mutation(0x1a8, '<I', 0x201, 'section sizes')

    def test_metadata_is_never_program_immutable_data(self):
        p = Candidate(image())
        for name, (start, end) in p.reserved:
            with self.subTest(name=name), self.assertRaises(Rejected):
                p.immutable(start, end - start)
        with self.assertRaisesRegex(Rejected, 'metadata'):
            p.immutable(0x2008, 9)  # Starts outside, overlaps debug directory at end.
        self.reject_mutation(0x401, '<I', 0x402040, 'metadata')

    def test_header_profiles_overflow_and_unsupported_startup(self):
        for offset, fmt, value, message in [
                (0x86, '<H', 4, 'COFF'), (0x96, '<H', 0x103, 'COFF'),
                (0xde, '<H', 0xc540, 'DLL'),
                (0xd0, '<I', 0x200000, 'resource'), (0xd4, '<I', 0x180, 'header'),
                (0x108, '<I', 0x2000, 'directory'), (0xf8 + 8 * 10, '<I', 0x2000, 'directory')]:
            with self.subTest(offset=offset):
                self.reject_mutation(offset, fmt, value, message)
        b = image()
        put(b, 0xb4, '<I', 0xffff0000)
        put(b, 0xd0, '<I', 0x10000)
        with self.assertRaisesRegex(Rejected, 'overflow'):
            Candidate(b)

    def test_section_overlap_permissions_and_entry_bounds(self):
        for offset, value, message in [
                (0x1b4, 0x400, 'raw overlap'), (0x1ac, 0x1000, 'placement'),
                (0x19c, 0xe0000020, 'permissions'), (0x1b4, 0xfffffe00, 'overflow'),
                (0xa8, 0x1010, 'whole range'), (0xa8, 0x2000, 'whole range')]:
            with self.subTest(offset=offset):
                self.reject_mutation(offset, '<I', value, message)

    def test_import_bounds_aliases_and_exact_identity(self):
        for offset, value, message in [
                (0x680, 0x2000, 'alias'), (0x68c, 0x20fc, 'whole range'),
                (0x600, 0x80000001, 'mismatch'), (0x604, 1, 'mismatch'),
                (0x684, 1, 'binding'), (0x694, 1, 'terminator'),
                (0xf8 + 12 * 8 + 4, 12, 'IAT directory')]:
            with self.subTest(offset=offset):
                self.reject_mutation(offset, '<I', value, message)
        self.reject_mutation(0x6d0, '<B', ord('M'), 'DLL name')
        self.reject_mutation(0x6c2, '<B', ord('X'), 'hint/name')

    def test_debug_kind_and_dual_address_validation(self):
        for offset, value, message in [
                (0x61c, 20, 'debug kind'), (0x61c, 2, 'debug kind'),
                (0x628, 0x641, 'disagreement'), (0x624, 0x2000, 'alias'),
                (0x620, 0, 'debug size'), (0x620, 4097, 'debug size'),
                (0x624, 0, 'whole range'), (0x620, 0xc1, 'whole range')]:
            with self.subTest(offset=offset):
                self.reject_mutation(offset, '<I', value, message)

    def test_relocation_block_validation_and_types(self):
        for value in (0, 7, 8, 10, 16, 0xfffffffc):
            with self.subTest(length=value):
                self.reject_mutation(0x804, '<I', value, 'block size')
        for value in (1, 0x2000, 0xfffff000):
            with self.subTest(page=value), self.assertRaises(Rejected):
                b = image()
                put(b, 0x800, '<I', value)
                Candidate(b)
        for kind in (1, 2, 4, 5, 10, 15):
            with self.subTest(kind=kind):
                self.reject_mutation(0x808, '<H', kind * 0x1000 + 1, 'unsupported relocation type')
        self.reject_mutation(0x808, '<H', 1, 'ABSOLUTE')
        self.reject_mutation(0x80a, '<H', 0x3001, 'overlapping')
        self.reject_mutation(0x80a, '<H', 0x3003, 'overlapping')
        self.reject_mutation(0x80a, '<H', 0x300e, 'whole range')

    def test_absolute_padding_and_complete_directory_consumption(self):
        b = image()
        put(b, 0x80a, '<H', 0)
        p = Candidate(b)
        self.assertEqual([(x.site, x.rva) for x in p.pointers], [(0x1001, 0x2060)])
        self.reject_mutation(0xf8 + 5 * 8 + 4, '<I', 11, 'block size')
        self.reject_mutation(0xf8 + 5 * 8 + 4, '<I', 16, 'whole range')

    def test_names_and_raw_order_do_not_define_section_roles(self):
        b = image()
        for at in (0x178, 0x1a0, 0x1c8):
            b[at:at + 8] = b'any-name'
        # Swap file placement of code and relocation data, keep their RVAs.
        code, reloc = bytes(b[0x400:0x600]), bytes(b[0x800:0xa00])
        b[0x400:0x600], b[0x800:0xa00] = reloc, code
        put(b, 0x18c, '<I', 0x800)
        put(b, 0x1dc, '<I', 0x400)
        p = Candidate(b)
        self.assertEqual(p.location(0x1001, 4, p.CODE), 0x801)
        self.assertEqual([(x.site, x.rva) for x in p.pointers], [(0x1001, 0x2060), (0x1007, 0x2000)])

    def test_duplicate_page_and_patched_metadata_reject(self):
        b = image()
        put(b, 0x1d0, '<I', 24)  # Declared relocation virtual extent.
        put(b, 0xf8 + 5 * 8 + 4, '<I', 24)
        b[0x80c:0x818] = b[0x800:0x80c]
        with self.assertRaisesRegex(Rejected, 'page order'):
            Candidate(b)
        # A well-formed relocation block targeting the read-only IAT itself is not code.
        b = image()
        put(b, 0x800, '<I', 0x2000)
        put(b, 0x808, '<HH', 0x3000, 0)
        with self.assertRaisesRegex(Rejected, 'whole range'):
            Candidate(b)

    def test_relocation_binding_is_bijective_and_typed(self):
        p = Candidate(image())
        for fields in [[], [(0x1001, 'immutable-buffer', 5)],
                       [(0x1001, 'immutable-buffer', 5)] * 2,
                       [(0x1002, 'immutable-buffer', 5), (0x1007, 'import-call', 4)],
                       [(0x1001, 'integer', 4), (0x1007, 'import-call', 4)],
                       [(0x1001, 'import-call', 4), (0x1007, 'immutable-buffer', 4)],
                       [(0x1001, 'immutable-buffer', 0xa1), (0x1007, 'import-call', 4)],
                       [(0x1001, 'immutable-buffer', 5), (0x1007, 'import-call', 8)]]:
            with self.subTest(fields=fields), self.assertRaises(Rejected):
                p.bind(fields)
        self.reject_mutation(0x401, '<I', 0x3fffff, 'below image')
        self.reject_mutation(0x401, '<I', 0x401000, 'whole range')

    def test_all_file_truncations_fail_explicitly(self):
        b = image()
        for length in range(len(b)):
            with self.subTest(length=length), self.assertRaises(Rejected):
                Candidate(b[:length])


if __name__ == '__main__':
    unittest.main()
