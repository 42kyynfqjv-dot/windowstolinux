"""Independent evidence-boundary checks; no native or Windows executions."""
import struct
import unittest

from formatter_binding import code_rows, edges, locale_state_evidence, mapped, operand, relative


def image(flags=0x60000020, count=1):
    data = bytearray(0x1200)
    struct.pack_into('<I', data, 60, 0x40)
    data[0x40:0x44] = b'PE\0\0'
    struct.pack_into('<HH', data, 0x44, 0x14c, count)
    struct.pack_into('<H', data, 0x54, 96)
    struct.pack_into('<H', data, 0x58, 0x10b)
    struct.pack_into('<I', data, 0x74, 0x400000)
    for i in range(count):
        section = 0xb8+40*i
        struct.pack_into('<IIII', data, section+8, 0x1000, 0x5000, 0x1000, 0x200)
        struct.pack_into('<I', data, section+36, flags)
    return data


def install(data, address, raw):
    offset = 0x200+address-0x405000
    data[offset:offset+len(raw)] = raw


class FormatterBindingTests(unittest.TestCase):
    def test_locale_mutation_evidence_does_not_attest_runtime_initialization(self):
        # Independent synthetic PE: pointer cells have raw bytes; the flag is
        # virtual zero fill. Neither kind of image data proves a live object.
        data = image()
        data.extend(b'\0' * (0x17500-len(data)))
        struct.pack_into('<IIII', data, 0xb8+8, 0x18000, 0x5000, 0x17300, 0x200)
        for address, raw in [
            (0x405219, '833d7cce4100007515'),
            (0x405222, 'a130c24100'), (0x405227, '8b0d34c24100'),
            (0x407126, '33c0b97cce4100408701c3'),
            (0x40b2f2, '807b0c007505e829beffff'),
            (0x40b367, '807b0c00740a8b43148b00a334c24100'),
            (0x41c230, '78563412'), (0x41c234, 'efcdab09'),
        ]:
            install(data, address, bytes.fromhex(raw))
        report = locale_state_evidence(data)
        self.assertFalse(report['runtime_state_proven'])
        self.assertFalse(report['emission_allowed'])
        self.assertEqual([w['file_backed_bytes'] for w in report['words']], [0, 4, 4])
        self.assertEqual([w['image_initial_word'] for w in report['words']],
                         [0, 0x12345678, 0x09abcdef])
        # Every effect-bearing edge and store must remain original. Mutating
        # one cannot leave a stale explanation in an otherwise valid report.
        for address in [0x405220, 0x40712e, 0x40b2f9, 0x40b36c, 0x40b373]:
            with self.subTest(address=address):
                changed = bytearray(data)
                changed[0x200+address-0x405000] ^= 1
                with self.assertRaises(ValueError):
                    locale_state_evidence(changed)

    def test_modifier_entry_is_after_table_not_the_linear_disassembler_row(self):
        data = image()
        install(data, 0x40582b, bytes.fromhex('008a412d3c46'))
        # An independently authored literal row crosses from table into code.
        listing = {0x582b: dict(code_hex='008a412d3c46', size=6)}
        rows = code_rows(data, listing, 0x40582c, 0x405831)
        self.assertEqual([(r['va'], r['code_hex']) for r in rows],
                         [(0x40582c, '8a412d'), (0x40582f, '3c46')])
        install(data, 0x40582e, b'\x2e')
        with self.assertRaisesRegex(ValueError, 'range disagreement'):
            code_rows(data, listing, 0x40582c, 0x405831)

    def test_full_initialized_range_permission_and_mapping_uniqueness(self):
        data = image()
        self.assertEqual(len(mapped(data, 0x405fff, 1, executable=True)), 1)
        for address, length in [(0x405fff, 2), (0x404fff, 2), (0xffffffff, 2), (0x405000, 0)]:
            with self.subTest(address=address, length=length), self.assertRaises(ValueError):
                mapped(data, address, length)
        with self.assertRaisesRegex(ValueError, 'not executable'):
            mapped(image(flags=0x40000040), 0x405000, 4, executable=True)
        with self.assertRaisesRegex(ValueError, 'writable'):
            mapped(image(flags=0xc0000040), 0x405000, 4, readonly=True)
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            mapped(image(count=2), 0x405000, 4)

    def test_address_bindings_require_original_opcode_and_complete_operand(self):
        data = image()
        install(data, 0x405010, bytes.fromhex('ff24850c584000'))
        self.assertEqual(operand(data, 0x405010, bytes.fromhex('ff2485')), 0x40580c)
        with self.assertRaisesRegex(ValueError, 'operand changed'):
            operand(data, 0x405010, bytes.fromhex('ff1485'))
        install(data, 0x405020, bytes.fromhex('e9dbffffff'))
        self.assertEqual(relative(data, 0x405020, 0xe9), 0x405000)
        with self.assertRaisesRegex(ValueError, 'edge changed'):
            relative(data, 0x405020, 0xe8)

    def test_dependency_inventory_preserves_indirect_calls_and_conditional_edges(self):
        rows = [dict(va=0x405000, code_hex='e8fb000000'),
                dict(va=0x405005, code_hex='ffd6'),
                dict(va=0x405007, code_hex='ff24850c584000'),
                dict(va=0x40500e, code_hex='75f0'),
                dict(va=0x405010, code_hex='0f8401000000')]
        result = edges(rows)
        self.assertEqual([r['kind'] for r in result],
                         ['call', 'indirect_call', 'indirect_jump', 'branch', 'branch'])
        self.assertEqual([r['target'] for r in result if 'target' in r],
                         [0x405100, 0x405000, 0x405017])
        self.assertTrue(all(r.get('effects_proven') is False
                            for r in result if r['kind'].startswith('indirect')))


if __name__ == '__main__':
    unittest.main()
