import unittest
from model import Records, Pointer, Encoded, Rejected


class Contract(unittest.TestCase):
    def setup_model(self):
        m = Records()
        frame = m.owner(0x1000, 128)
        scope = m.owner(0x5000, 16)
        m.initialize_cookie(0xa5a5a5a5)
        return m, frame, scope

    def test_literal_encoding_and_alias(self):
        m, f, s = self.setup_model()
        e = m.encode(s)
        self.assertEqual(e.bits, 0xa5a5f5a5)
        m.store(f, e)
        alias = m.offset(f, 0)
        self.assertEqual(m.decode(m.load(alias)), s)
        with self.assertRaises(Rejected):
            m.decode(e.bits)

    def test_partial_write_and_unknown_external_effect(self):
        m, f, s = self.setup_model()
        m.store(f, s)
        m.invalidate(m.offset(f, 1), 1)
        with self.assertRaises(Rejected): m.load(f)
        m.store(f, s)
        t = m.thread()
        m.external_unknown(t)
        with self.assertRaises(Rejected): m.load(f)
        with self.assertRaises(Rejected): m.register(t, f, m.encode(s))

    def test_wrong_process_and_stale_target(self):
        m, f, s = self.setup_model()
        other, _, q = self.setup_model()
        with self.assertRaises(Rejected): m.store(f, q)
        m.store(f, s)
        m.retire(s)
        with self.assertRaises(Rejected): m.load(f)
        new = m.owner(0x5000, 16)
        with self.assertRaises(Rejected): m.store(f, s)
        m.store(f, new)

    def test_nested_restore_and_thread_isolation(self):
        m, f, s = self.setup_model()
        t, u = m.thread(), m.thread()
        g = m.offset(f, 32)
        m.register(t, f, m.encode(s))
        m.register(t, g, m.encode(s))
        with self.assertRaises(Rejected): m.restore(t, f)
        with self.assertRaises(Rejected): m.restore(u, g)
        with self.assertRaises(Rejected): m.register(u, g, m.encode(s))
        m.restore(t, g)
        m.restore(t, f)
        self.assertEqual(m.threads[t], [])

    def test_cookie_reinitialization_and_tampered_encoding(self):
        m, f, s = self.setup_model()
        e = m.encode(s)
        m.initialize_cookie(7)
        with self.assertRaises(Rejected): m.decode(e)
        t = m.thread()
        m.register(t, f, m.encode(s))
        with self.assertRaises(Rejected): m.initialize_cookie(8)
        with self.assertRaises(Rejected): m.decode(Encoded(s, m.version, 0))

    def test_exception_cannot_become_normal_return(self):
        m, f, s = self.setup_model()
        t = m.thread()
        m.register(t, f, m.encode(s))
        self.assertEqual(m.exception(t, 0xe0420001), ('dispatch-required', 0xe0420001))
        with self.assertRaises(Rejected): m.restore(t, f)
        with self.assertRaises(Rejected): m.retire(f)

    def test_full_word_and_registration_bounds(self):
        m, f, s = self.setup_model()
        last = m.offset(f, 124)
        m.store(last, 0xffffffff)
        self.assertEqual(m.load(last), 0xffffffff)
        with self.assertRaises(Rejected): m.offset(f, 125)
        with self.assertRaises(Rejected): m.register(m.thread(), last, m.encode(s))
        with self.assertRaises(Rejected): m.offset(f, 2**32)

    def test_unknown_and_integer_domains(self):
        m = Records()
        p = m.owner(4096, 16)
        with self.assertRaises(Rejected): m.encode(p)
        for x in [True, 1.5, -1, 2**32]:
            with self.assertRaises(Rejected): m.initialize_cookie(x)
            with self.assertRaises(Rejected): m.store(p, x)
        with self.assertRaises(Rejected): m.load(p)

    def test_active_alias_write_and_overlap_block_restoration(self):
        m, f, s = self.setup_model()
        t, u = m.thread(), m.thread()
        m.register(t, f, m.encode(s))
        with self.assertRaises(Rejected): m.register(u, m.offset(f, 4), m.encode(s))
        m.invalidate(m.offset(f, 15), 1)
        with self.assertRaises(Rejected): m.restore(t, f)

    def test_unknown_effect_invalidates_other_thread_cookie_facts(self):
        m, f, s = self.setup_model()
        t, u = m.thread(), m.thread()
        m.register(t, f, m.encode(s))
        m.external_unknown(u)
        with self.assertRaises(Rejected): m.restore(t, f)
        with self.assertRaises(Rejected): m.encode(s)

    def test_unresolved_exception_blocks_ordinary_operations_atomically(self):
        m, f, s = self.setup_model()
        m.store(f, 42)
        e = m.encode(s)
        t = m.thread()
        m.exception(t, 0xe0420001)
        before = dict(m.cells)
        for action in [lambda: m.load(f), lambda: m.store(f, 99),
                       lambda: m.encode(s), lambda: m.decode(e),
                       lambda: m.owner(0x6000, 16), lambda: m.thread(),
                       lambda: m.offset(f, 4), lambda: m.retire(s)]:
            with self.assertRaises(Rejected): action()
        self.assertEqual(m.cells, before)
