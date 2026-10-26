"""Literal byte layouts/expectations independent of production and fixture builders."""
import struct
import unittest
from permissioned_intake import Image, Rejected, end32


def put(b, at, fmt, *values):
    struct.pack_into('<' + fmt, b, at, *values)


def specimen(four=False):
    # Table starts178; headers[0,400), code[400,600), RO[600,800).
    # Four-section case adds RW[800,a00), relocation[a00,c00).
    # RW virtual[3000,3204) includes four zero-fill bytes after raw[3000,3200).
    b = bytearray(0xc00 if four else 0x800)
    b[:2] = b'MZ'
    put(b, 60, 'I', 0x80)
    b[0x80:0x84] = b'PE\0\0'
    put(b, 0x84, 'HHIIIHH', 0x14c, 4 if four else 2, 0, 0, 0, 224, 0x102)
    put(b, 0x98, 'H', 0x10b)
    put(b, 0xa8, 'I', 0x1000)
    put(b, 0xb4, 'III', 0x400000, 4096, 512)
    put(b, 0xd0, 'II', 0x5000 if four else 0x3000, 0x400)
    put(b, 0xdc, 'HHIIII', 3, 0x8540, 0x100000, 4096, 0x100000, 4096)
    put(b, 0xf4, 'I', 16)
    rows = [(0x20, 0x1000, 512, 0x400, 0x60000020),
            (0x80, 0x2000, 512, 0x600, 0x40000040)]
    if four:
        rows += [(0x204, 0x3000, 512, 0x800, 0xc0000040),
                 (12, 0x4000, 512, 0xa00, 0x42000040)]
        put(b, 0x120, 'II', 0x4000, 12)
        put(b, 0xa00, 'IIHH', 0x1000, 12, 0x3001, 0x3007)
        put(b, 0x401, 'I', 0x403000)
        put(b, 0x407, 'I', 0x403200)
    for i, (vs, rva, size, raw, flags) in enumerate(rows):
        put(b, 0x180 + 40 * i, 'IIIIIIHHI', vs, rva, size, raw, 0, 0, 0, 0, flags)
    put(b, 0x128, 'II', 0x2000, 28)
    put(b, 0x600, 'IIHHIIII', 0, 0, 0, 0, 13, 8, 0x2020, 0x620)
    b[0x620:0x628] = b'metadata'
    b[0x640:0x645] = b'Hello'
    return b


class PermissionedDesign(unittest.TestCase):
    def mutation(self, at, fmt, values, reason, four=False):
        b = specimen(four)
        put(b, at, fmt, *values)
        with self.assertRaisesRegex(Rejected, reason):
            Image(b)

    def test_two_section_importless_and_nonrelocatable(self):
        p = Image(specimen())
        self.assertEqual([(s.rva, s.role) for s in p.sections], [(0x1000, 'code'), (0x2000, 'immutable')])
        self.assertEqual(p.immutable(0x2040, 5), b'Hello')
        self.assertEqual(p.pointers, [])
        self.assertEqual(p.report()['blockers'], ['instruction-ABI-and-provenance-proof-not-run'])
        self.assertFalse(p.report()['emission_allowed'])
        self.assertEqual(p.report()['base_evidence'], 'preferred-header-only')

    def test_four_section_provenance_is_unbound_and_writable(self):
        p = Image(specimen(True))
        self.assertEqual([(x['site'], x['rva'], x['role'], x['bound']) for x in p.pointers],
                         [(0x1001, 0x3000, 'writable', False), (0x1007, 0x3200, 'writable', False)])
        self.assertIn('writable-memory-unimplemented', p.blockers)
        self.assertEqual(p.locate(0x3200, 4, backed=False)[0].role, 'writable')
        for rva, size in [(0x31ff, 2), (0x3200, 1), (0x3203, 2)]:
            with self.subTest(rva=rva), self.assertRaises(Rejected):
                p.locate(rva, size)
        with self.assertRaises(Rejected):
            p.locate(0x3203, 2, backed=False)
        with self.assertRaisesRegex(Rejected, 'immutable'):
            p.immutable(0x3000, 4)

    def test_zero_raw_bss_has_no_file_backed_access(self):
        b = specimen(True)
        put(b, 0x1d8, 'II', 0, 0)
        put(b, 0x1ec, 'I', 0xc0000080)
        p = Image(b)
        self.assertEqual(p.locate(0x3000, 0x204, backed=False)[0].role, 'writable-zero')
        self.assertEqual(p.immutable(0x2040, 5), b'Hello')  # Empty BSS cannot break unrelated lookups.
        with self.assertRaises(Rejected):
            p.locate(0x3000, 1)
        self.mutation(0x1d8, 'II', (0, 0), 'empty raw', True)

    def test_padding_headers_gaps_code_and_complete_width(self):
        p = Image(specimen())
        self.assertEqual(p.immutable(0x207f, 1), b'\0')
        for start, length in [(0x207f, 2), (0x2080, 1), (0x400, 1), (0x1800, 1),
                              (0x1000, 1), (0xffffffff, 2), (0x2040, 0)]:
            with self.subTest(start=start), self.assertRaises(Rejected):
                p.immutable(start, length)
        for entry in (0x1020, 0x2000, 0x2080, 0x3000):
            self.mutation(0xa8, 'I', (entry,), 'range|entry')

    def test_metadata_spans_and_debug_dual_address(self):
        p = Image(specimen())
        for start, length in [(0x2000, 1), (0x2020, 1), (0x201c, 5)]:
            with self.subTest(start=start), self.assertRaisesRegex(Rejected, 'metadata'):
                p.immutable(start, length)
        for at, value, reason in [(0x618, 0x621, 'disagreement'), (0x614, 0x2000, 'alias'),
                                   (0x610, 0, 'size'), (0x60c, 2, 'kind'),
                                   (0x614, 0x207c, 'whole section')]:
            self.mutation(at, 'I', (value,), reason)

    def test_section_names_file_order_and_incidental_aggregates(self):
        b = specimen()
        b[0x178:0x180] = b'not-code'
        b[0x1a0:0x1a8] = b'not-data'
        b[0x400:0x600], b[0x600:0x800] = b[0x600:0x800], b[0x400:0x600]
        put(b, 0x18c, 'I', 0x600)
        put(b, 0x1b4, 'I', 0x400)
        put(b, 0x418, 'I', 0x420)  # Debug payload file pointer moves with bytes.
        put(b, 0x9c, 'III', 123, 456, 789)  # Not authoritative bounds.
        put(b, 0xac, 'II', 17, 23)  # BaseOfCode/BaseOfData not used to locate a section.
        put(b, 0x96, 'H', 0x30e)  # Executable + 32-bit + stripped debug/legacy symbols.
        self.assertEqual(Image(b).immutable(0x2040, 5), b'Hello')

    def test_directory_count_and_optional_size_are_authoritative(self):
        b = specimen()
        put(b, 0x128, 'II', 0, 0)
        put(b, 0xf4, 'I', 0)
        p = Image(b)
        self.assertEqual(p.dirs, {})
        self.assertEqual(p.immutable(0x2000, 1), b'\0')  # No declared metadata here.
        # Short optional header: move the table to its declared location.
        b[0xf8:0x148] = b[0x178:0x1c8]
        put(b, 0x94, 'H', 96)
        self.assertEqual(len(Image(b).sections), 2)
        for at, fmt, value in [(0xf4, 'I', 17), (0x94, 'H', 95), (0x94, 'H', 200)]:
            self.mutation(at, fmt, (value,), 'directory count|short optional')
        self.mutation(0xf4, 'I', (0,), 'optional extension')
        self.mutation(0x120, 'II', (0x2000, 0), 'incomplete pair')

    def test_startup_and_import_obligations_block_metadata_access(self):
        for index in (0, 1, 2, 3, 7, 8, 9, 10, 11, 12, 13, 14, 15):
            b = specimen()
            put(b, 0xf8 + index * 8, 'II', 0x2050, 8)
            p = Image(b)
            expected = 'import-closure-unvalidated' if index in (1, 12) else 'unsupported-directory-' + str(index)
            self.assertIn(expected, p.blockers)
            self.assertFalse(p.metadata_closed)
            self.assertFalse(p.report()['emission_allowed'])
            with self.assertRaisesRegex(Rejected, 'closure incomplete'):
                p.immutable(0x2040, 5)
        self.mutation(0x140, 'II', (0x2000, 8), 'alias')  # TLS aliases debug.
        self.mutation(0x148, 'II', (0x207c, 8), 'whole section')

    def test_certificate_uses_file_offset_and_stays_unsupported(self):
        b = specimen() + bytes(16)
        put(b, 0x118, 'II', 0x800, 16)
        p = Image(b)
        self.assertIn('unsupported-directory-4', p.blockers)
        self.assertFalse(p.metadata_closed)
        self.mutation(0x118, 'II', (0x600, 8), 'certificate file alias')
        self.mutation(0x118, 'II', (0x2000, 8), 'truncated file')

    def test_file_virtual_overlap_overflow_and_alignment(self):
        for at, value, reason in [(0x1b4, 0x400, 'raw alias'), (0x1b4, 0, 'raw alias'),
                                   (0x1ac, 0x1000, 'virtual extent/order'),
                                   (0x1a8, 0xfffffff0, 'nonwritable zero-fill'),
                                   (0x18c, 0xfffffe00, 'overflow'),
                                   (0x1b0, 0x201, 'raw alignment'),
                                   (0x1b4, 0x601, 'raw alignment'),
                                   (0xd0, 0x2000, 'image bounds'), (0xd0, 0x4000, 'image extent'),
                                   (0xd4, 0x100, 'header: extent')]:
            self.mutation(at, 'I', (value,), reason)
        self.mutation(0x1d0, 'I', (0xfffffff0,), 'overflow', True)
        self.assertEqual(end32(0xfffffff0, 15), 0xffffffff)
        with self.assertRaisesRegex(Rejected, 'overflow'):
            end32(0xfffffff0, 16)
        b = specimen(); put(b, 0xb4, 'I', 0xffff0000); put(b, 0xd0, 'I', 0x10000)
        with self.assertRaisesRegex(Rejected, 'overflow'):
            Image(b)

    def test_execution_permission_architecture_and_resource_policy(self):
        for flags in (0xe0000020, 0x20000020, 0xd0000040, 0x40000020, 0x60000040):
            self.mutation(0x19c, 'I', (flags,), 'permissions')
        for coff in (0x2102, 0x1102, 0x100, 0x122):
            self.mutation(0x96, 'H', (coff,), 'COFF execution')
        for at, fmt, value, reason in [(0x84, 'H', 0x8664, 'architecture'),
                                      (0x98, 'H', 0x20b, 'architecture'),
                                      (0x86, 'H', 9, 'section count'),
                                      (0xde, 'H', 0xc540, 'DLL flags'),
                                      (0xdc, 'H', 2, 'subsystem'),
                                      (0xd0, 'I', 0x200000, 'limit: image'),
                                      (0xb8, 'I', 512, 'alignment')]:
            self.mutation(at, fmt, (value,), reason)

    def test_relocation_types_lengths_sites_and_destination_provenance(self):
        for at, fmt, value, reason in [(0xa04, 'I', 8, 'block length'),
                (0xa04, 'I', 16, 'block length'), (0xa00, 'I', 1, 'page order'),
                (0xa08, 'H', 0xa001, 'unsupported type'), (0xa08, 'H', 1, 'ABSOLUTE'),
                (0xa0a, 'H', 0x3001, 'overlapping'), (0xa0a, 'H', 0x3003, 'overlapping'),
                (0xa0a, 'H', 0x301e, 'whole section'),
                (0x401, 'I', 0x3fffff, 'below preferred'),
                (0x401, 'I', 0x402020, 'metadata'), (0x401, 'I', 0x401000, 'destination role'),
                (0x401, 'I', 0x403204, 'whole section'), (0x96, 'H', 0x103, 'stripped contradiction')]:
            self.mutation(at, fmt, (value,), reason, True)
        b = specimen(True); put(b, 0xa0a, 'H', 0)
        self.assertEqual(len(Image(b).pointers), 1)
        b = specimen(True); put(b, 0xa00, 'I', 0x2000)
        with self.assertRaisesRegex(Rejected, 'site must be code'):
            Image(b)

    def test_relocation_pages_and_metadata_permission(self):
        b = specimen(True); put(b, 0x124, 'I', 24); put(b, 0x1f8, 'I', 24)
        b[0xa0c:0xa18] = b[0xa00:0xa0c]
        with self.assertRaisesRegex(Rejected, 'page order'):
            Image(b)
        self.mutation(0x214, 'I', (0x40000040,), 'directory policy', True)

    def test_snapshot_identity_and_determinism(self):
        b = specimen(True); p = Image(b); before = p.report()
        b[0x800] = 9
        q = Image(b)
        self.assertNotEqual(p.identity, q.identity)
        self.assertEqual(p.report(), before)
        self.assertTrue(all(x['image'] == p.identity for x in p.pointers))
        self.assertEqual(q.report(), Image(b).report())

    def test_all_truncations_reject_explicitly(self):
        b = specimen()
        for n in range(len(b)):
            with self.subTest(length=n), self.assertRaises(Rejected):
                Image(b[:n])


if __name__ == '__main__':
    unittest.main()
