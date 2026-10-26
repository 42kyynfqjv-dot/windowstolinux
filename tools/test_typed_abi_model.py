"""Independent literal expectations and concrete byte-stack traces for SUB-517.

No imports from production, linker prototype or fixture generators. These are
contract tests, not end-to-end PE translation or a general x86 interpreter.
"""
import copy
import struct
import unittest
from typed_abi_model import (Field, Image, ImportSlot, Integer, Machine, Pointer,
                             Rejected, Unknown, Word)


FIELDS = [Field(0x1003, 5, 0x1004, 'push32'),
          Field(0x100a, 6, 0x100c, 'import-call')]
RECORDS = [(0x1004, 0x402008), (0x100c, 0x402000)]


def setup():
    image = Image()
    values = image.bind(RECORDS, FIELDS)
    return Machine(image), values[0x1004], values[0x100c]


class ConcreteStack:
    """Independently specified little-endian word storage at numeric addresses."""
    def __init__(self, esp, initial_return):
        self.esp = esp
        self.memory = {}
        self.store(initial_return)

    def store(self, value):
        for i, byte in enumerate(struct.pack('<I', value)):
            self.memory[self.esp + i] = byte

    def push(self, value):
        self.esp -= 4
        self.store(value)

    def read(self, displacement=0):
        return int.from_bytes(bytes(self.memory[self.esp + displacement + i]
                                    for i in range(4)), 'little')

    def pop(self):
        value = self.read()
        self.esp += 4
        return value


class TypedAbiTests(unittest.TestCase):
    def test_observed_trace_against_concrete_stack(self):
        # 3 bases x 4 incoming ESI values x 2 aligned ESPs: 24 concrete traces.
        # Bases are arithmetic samples, not claims of Windows execution at each.
        for base in (0x10000, 0x400000, 0x680000):
            for incoming in (0, 0x12345678, 0x80000000, 0xffffffff):
                for esp in (0x120000, 0x7fff0000):
                    with self.subTest(base=base, incoming=incoming, esp=esp):
                        m, pointer, slot = setup()
                        original = m.esi  # Symbolic identity must survive unchanged.
                        s = ConcreteStack(esp, 0x76543210)
                        m.save_esi(); s.push(incoming)
                        for value in (Integer(5), pointer, Integer(1)):
                            m.push(value)
                        for value in (5, base + 0x2008, 1):
                            s.push(value)
                        s.push(base + 0x1010)
                        self.assertEqual((s.read(4), s.read(8), s.read(12)),
                                         (1, base + 0x2008, 5))
                        self.assertEqual(m.write(slot), b'Hello')
                        self.assertEqual(s.pop(), base + 0x1010)
                        m.push(Integer(5)); s.push(5)
                        m.push(Integer(7)); s.push(7)
                        m.move_eax_to_esi()
                        self.assertEqual(m.esi, Integer(5))
                        m.call(0x101b); s.push(base + 0x101b)
                        self.assertEqual([w.kind for w in m.words],
                                         ['entry', 'saved-esi', 'data', 'data',
                                          'data', 'data', 'data', 'return'])
                        self.assertEqual((m.argument(1), m.argument(2)), (Integer(7), Integer(5)))
                        self.assertEqual((s.read(4), s.read(8)), (7, 5))
                        m.eax = m.argument(1)
                        m.add_eax(m.argument(2))
                        self.assertEqual(m.eax, Integer(12))
                        self.assertEqual(m.ret(), 0x101b)
                        self.assertEqual(s.pop(), base + 0x101b)
                        m.cleanup_add(5); s.esp += 20
                        self.assertIsNone(m.flags)
                        self.assertEqual((m.eax, m.esi), (Integer(12), Integer(5)))
                        m.eax = Integer(0)  # Independent expected success branch.
                        m.restore_esi()
                        self.assertIs(m.esi, original)
                        self.assertEqual(s.pop(), incoming)
                        m.ret()
                        self.assertEqual(s.esp, esp)
                        self.assertEqual(s.pop(), 0x76543210)
                        self.assertTrue(m.halted)

    def test_failure_return_also_restores_esi(self):
        m, _, _ = setup()
        m.save_esi()
        m.eax = Integer(99)
        m.move_eax_to_esi()
        with self.assertRaisesRegex(Rejected, 'ESI not restored'):
            m.ret()
        m.restore_esi()
        m.ret()
        self.assertTrue(m.halted)

    def test_nested_and_shared_callee_context(self):
        m, _, _ = setup()
        initial = m.esi
        for continuation, value in ((0x1100, 7), (0x1200, 11)):
            m.push(Integer(value))
            m.call(continuation)
            caller_esi = m.esi
            m.save_esi()
            m.eax = Integer(value)
            m.move_eax_to_esi()
            m.push(Integer(value + 1))
            m.call(0x1300)
            m.eax = m.argument(1)
            self.assertEqual(m.ret(), 0x1300)
            self.assertEqual(m.esi, Integer(value))
            m.cleanup_add(1)
            m.restore_esi()
            self.assertIs(m.esi, caller_esi)
            self.assertEqual(m.ret(), continuation)
            m.cleanup_add(1)
        self.assertIs(m.esi, initial)
        self.assertEqual(m.eax, Integer(12))
        m.ret()

    def test_unknown_identity_is_not_wildcard(self):
        m, _, _ = setup()
        m.eax = Integer(0)
        m.esi = Unknown(object())
        with self.assertRaisesRegex(Rejected, 'ESI not restored'):
            m.ret()
        with self.assertRaisesRegex(Rejected, 'scalar arithmetic'):
            m.eax = Unknown(object())
            m.add_eax(Integer(1))

    def test_pointer_copy_and_save_preserve_provenance(self):
        m, pointer, _ = setup()
        m.save_esi()
        m.eax = pointer
        m.move_eax_to_esi()
        m.call(0x1234)
        m.save_esi()
        m.eax = Integer(42)
        m.move_eax_to_esi()
        m.restore_esi()
        self.assertIs(m.esi, pointer)
        m.ret()
        m.restore_esi()
        m.eax = Integer(0)
        m.ret()

    def test_pointer_forgery_and_cross_image_reject(self):
        m, pointer, slot = setup()
        other, other_pointer, _ = setup()
        for bad in (Integer(0x402008), Pointer(m.image.identity, 0x2008),
                    other_pointer, slot):
            with self.subTest(value=bad), self.assertRaises(Rejected):
                m.image.buffer(bad, Integer(5))
        with self.assertRaises(Rejected):
            other.push(pointer)
        with self.assertRaises(Rejected):
            m.push(slot)
        with self.assertRaises(Rejected):
            m.write(ImportSlot(m.image.identity, 0x2000))

    def test_pointer_arithmetic_and_returns_reject(self):
        m, pointer, _ = setup()
        for value in (pointer, Unknown(object())):
            m.eax = value
            with self.assertRaises(Rejected):
                m.add_eax(Integer(0))
            with self.assertRaises(Rejected):
                m.ret()
        m.call(0x1200)
        m.eax = pointer
        with self.assertRaisesRegex(Rejected, 'scalar return'):
            m.ret()

    def test_save_return_and_owner_boundaries(self):
        m, _, _ = setup()
        m.eax = Integer(0)
        for operation in (m.restore_esi, lambda: m.cleanup_add(1)):
            with self.assertRaises(Rejected):
                operation()
        m.save_esi()
        with self.assertRaisesRegex(Rejected, 'save/return/foreign'):
            m.cleanup_add(1)
        m.call(0x1111)
        for operation in (m.restore_esi, lambda: m.cleanup_add(1), lambda: m.argument(1)):
            with self.assertRaises(Rejected):
                operation()
        m.save_esi()
        with self.assertRaisesRegex(Rejected, 'protected return'):
            m.ret()
        with self.assertRaisesRegex(Rejected, 'unmodified callee ESP'):
            m.argument(1)
        m.restore_esi()
        m.ret()
        m.restore_esi()
        m.push(Integer(0x1111))
        with self.assertRaisesRegex(Rejected, 'balanced entry return'):
            m.ret()

    def test_cleanup_is_atomic_and_invalidates_flags(self):
        m, _, _ = setup()
        m.save_esi()
        m.push(Integer(7))
        before = list(m.words)
        with self.assertRaises(Rejected):
            m.cleanup_add(2)
        self.assertEqual(m.words, before)
        m.flags = (False, True, False, False)
        m.cleanup_add(1)
        with self.assertRaisesRegex(Rejected, 'unknown flags'):
            m.require_flags()
        # A later CMP must compute flags from known integers. This model does not
        # pretend to validate CMP/branch arithmetic or emitted Rust.

    def test_argument_order_bounds_and_types(self):
        m, pointer, _ = setup()
        m.push(Integer(5)); m.push(pointer); m.call(0x1200)
        self.assertIs(m.argument(1), pointer)
        self.assertEqual(m.argument(2), Integer(5))
        for ordinal in (0, 3, -1):
            with self.assertRaises(Rejected):
                m.argument(ordinal)
        m.eax = Integer(7)
        with self.assertRaises(Rejected):
            m.add_eax(m.argument(1))

    def test_exact_join_includes_context_and_unknown_identity(self):
        m, pointer, _ = setup()
        twin = copy.copy(m)
        self.assertIs(m.join(twin), m)
        for attribute, value in (('eax', Integer(0)), ('esi', Unknown(object())),
                                 ('flags', (False, False, False, False)),
                                 ('words', [Word('entry', 1)]), ('serial', 1)):
            twin = copy.copy(m)
            setattr(twin, attribute, value)
            with self.subTest(attribute=attribute), self.assertRaises(Rejected):
                m.join(twin)
        twin = copy.copy(m)
        m.eax = pointer
        twin.eax = Integer(0x402008)
        with self.assertRaises(Rejected):
            m.join(twin)
        other, _, _ = setup()
        with self.assertRaises(Rejected):
            m.join(other)

    def test_relocation_bijection_and_roles(self):
        self.assertEqual(set(Image().bind(RECORDS, FIELDS)), {0x1004, 0x100c})
        cases = [
            (RECORDS[:1], FIELDS), (RECORDS, FIELDS[:1]),
            (RECORDS + [(0x1050, 0x402008)], FIELDS),  # Unreachable extra record.
            ([RECORDS[0], RECORDS[0]], FIELDS),
            (RECORDS, [FIELDS[0], FIELDS[0]]),
            (RECORDS, [Field(0x1003, 5, 0x1003, 'push32'), FIELDS[1]]),
            (RECORDS, [Field(0x1003, 5, 0x1004, 'integer'), FIELDS[1]]),
            ([(0x1004, 0x402000), RECORDS[1]], FIELDS),
            ([RECORDS[0], (0x100c, 0x402008)], FIELDS),
            ([(0x1004, 0x401000), RECORDS[1]], FIELDS),
            ([(0x1004, 0x3fffff), RECORDS[1]], FIELDS),
        ]
        for records, fields in cases:
            with self.subTest(records=records, fields=fields), self.assertRaises(Rejected):
                Image().bind(records, fields)
        # An extra annotated operand on the other successor also needs a record.
        both = FIELDS + [Field(0x1040, 5, 0x1041, 'push32')]
        with self.assertRaises(Rejected):
            Image().bind(RECORDS, both)
        self.assertEqual(len(Image().bind(RECORDS + [(0x1041, 0x402008)], both)), 3)

    def test_buffer_full_range_and_bytes(self):
        for data, count in ((b'Hello', 6), (b'Hello', 0), (b'A' * 65, 65),
                            (b'Hi\n', 3), (b'Hi\x1a', 3), (b'Hi\x00', 3)):
            image = Image(data=data)
            values = image.bind(RECORDS, FIELDS)
            with self.subTest(data=data, count=count), self.assertRaises(Rejected):
                image.buffer(values[0x1004], Integer(count))
        with self.assertRaises(Rejected):
            Image(base=0xffff0000, start=0xffff)

    def test_external_call_preserves_esi_and_args_not_flags(self):
        m, pointer, slot = setup()
        initial = m.esi
        for value in (Integer(5), pointer, Integer(1)):
            m.push(value)
        words = list(m.words)
        m.flags = (False, True, False, False)
        self.assertEqual(m.write(slot), b'Hello')
        self.assertEqual(m.eax, Integer(5))
        self.assertIs(m.esi, initial)
        self.assertEqual(m.words, words)
        self.assertIsNone(m.flags)
        m.words[-1] = Word('data', 999, Integer(1))
        with self.assertRaisesRegex(Rejected, 'owned output arguments'):
            m.write(slot)

    def test_preserved_flags_and_return_context_join(self):
        m, _, _ = setup()
        flags = (True, False, True, False)
        m.flags = flags
        m.save_esi()
        m.eax = Integer(12)
        m.move_eax_to_esi()
        m.push(Integer(7))
        m.call(0x1200)
        self.assertEqual(m.flags, flags)
        self.assertEqual(m.argument(1), Integer(7))
        twin = copy.copy(m)
        twin.frames = list(m.frames)
        twin.frames[-1] = type(m.frames[-1])(m.owner, m.esi, 0x1201)
        with self.assertRaisesRegex(Rejected, 'context join'):
            m.join(twin)
        self.assertEqual(m.ret(), 0x1200)
        self.assertEqual(m.flags, flags)
        m.cleanup_add(1)
        m.flags = flags
        m.restore_esi()
        m.ret()
        self.assertEqual(m.flags, flags)

    def test_limits_and_terminal_state(self):
        m, _, _ = setup()
        for _ in range(32):
            m.call(0x1200)
        with self.assertRaisesRegex(Rejected, '32-call'):
            m.call(0x1200)
        m, _, _ = setup()
        for _ in range(128):
            m.push(Integer(0))
        with self.assertRaisesRegex(Rejected, '128-word'):
            m.save_esi()
        m, pointer, slot = setup()
        for _ in range(125):
            m.push(Integer(0))
        for value in (Integer(5), pointer, Integer(1)):
            m.push(value)
        with self.assertRaisesRegex(Rejected, 'external call resource'):
            m.write(slot)
        m, _, _ = setup()
        m.eax = Integer(256)
        with self.assertRaisesRegex(Rejected, 'exit range'):
            m.ret()
        m.eax = Integer(0)
        m.ret()
        for operation in (m.ret, m.save_esi, lambda: m.push(Integer(1)),
                          lambda: m.call(0x1200), lambda: m.cleanup_add(1)):
            with self.assertRaisesRegex(Rejected, 'terminal state'):
                operation()


if __name__ == '__main__':
    unittest.main()
