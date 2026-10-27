import unittest
from model import Space, Module, Reject


class Contracts(unittest.TestCase):
    def test_ranges_and_aliases(self):
        s=Space();s.map(0x1000,8,'image',zero=True)
        s.write(0x1001,b'ABC');self.assertEqual(s.read(0x1000,5),b'\0ABC\0')
        for base,size in [(0x1007,2),(0xffffffff,2),(0,4),(-1,4),(True,4),(0x2000,1.5)]:
            with self.assertRaises(Reject):s.map(base,size,'x')
        s.map(0x1008,8,'other',zero=True)
        with self.assertRaises(Reject):s.read(0x1007,2)

    def test_permission_and_unknown_bytes(self):
        s=Space();s.map(0x1000,4,'heap');s.write(0x1000,b'X')
        with self.assertRaises(Reject):s.read(0x1000,2)
        s.map(0x2000,4,'image',zero=True,writable=False)
        with self.assertRaises(Reject):s.write(0x2000,b'X')
        self.assertEqual(s.read(0x2000,4),b'\0'*4)

    def test_raw_address_reuse_is_not_hidden_tagging(self):
        s=Space();old=s.map(0x1000,4,'heap');s.write(0x1000,b'old!');s.release(old)
        new=s.map(0x1000,4,'heap');s.write(0x1000,b'new!')
        with self.assertRaises(Reject):s.capability(old)
        with self.assertRaises(Reject):s.capability((new[0],new[1],'other',new[3]))
        self.assertEqual(s.read(0x1000,4),b'new!')
        other=Space();temporary=other.map(0x1000,4,'heap');other.release(temporary)
        foreign=other.map(0x1000,4,'heap')
        self.assertEqual(new[:3],foreign[:3])  # only process identity differs
        with self.assertRaises(Reject):s.capability(foreign)

    def test_reallocation_outcomes(self):
        s=Space();old=s.map(0x1000,4,'heap');s.write(0x1000,b'AB')
        self.assertIsNone(s.move_resize(old,0x2000,8,fail=True))
        self.assertEqual(s.read(0x1000,2),b'AB');s.capability(old)
        new=s.move_resize(old,0x2000,8,zero_tail=True)
        self.assertEqual(s.read(0x2000,2),b'AB');self.assertEqual(s.read(0x2004,4),b'\0'*4)
        with self.assertRaises(Reject):s.read(0x2002,2)
        with self.assertRaises(Reject):s.capability(old)
        small=s.move_resize(new,0x3000,1);self.assertEqual(s.read(small[0],1),b'A')

    def test_failed_precondition_preserves_old_region(self):
        s=Space();old=s.map(0x1000,8,'heap',zero=True)
        with self.assertRaises(Reject):s.move_resize(old,0x1004,8)
        self.assertEqual(s.read(0x1000,8),b'\0'*8);s.capability(old)

    def test_read_epoch_and_failure_contract(self):
        s=Space();s.map(0x1000,8,'frame');s.write(0x1000,b'abcdefgh')
        self.assertFalse(s.external('unchanged_failure',0x1000,8))
        self.assertEqual(s.read(0x1000,8),b'abcdefgh')
        s.external('prefix_success',0x1000,8,b'XY',2)
        self.assertEqual(s.read(0x1000,2),b'XY')
        with self.assertRaises(Reject):s.read(0x1002,1)
        for effect,count in [('unknown',0),('prefix_success',9),('prefix_success',-1)]:
            with self.assertRaises(Reject):s.external(effect,0x1000,8,b'',count)
        self.assertEqual(s.read(0x1000,2),b'XY')

    def test_module_order_failure_and_no_rollback_claim(self):
        m=Module(['tls','entry'])
        with self.assertRaises(Reject):m.enter()
        with self.assertRaises(Reject):m.bind(False)
        m.bind(True)
        with self.assertRaises(Reject):m.complete('entry',True)
        m.complete('tls',True);m.complete('entry',False)
        with self.assertRaises(Reject):m.enter()
        self.assertEqual(m.position,1);self.assertEqual(m.state,'failed')

    def test_module_success_requires_every_declared_effect(self):
        m=Module(['a','b']);m.bind(True);m.complete('a',True)
        with self.assertRaises(Reject):m.enter()
        m.complete('b',True);m.enter();self.assertEqual(m.state,'running')
        with self.assertRaises(Reject):m.enter()

    def test_budget_and_wrap_do_not_become_valid_access(self):
        s=Space();s.map(0xfffffff8,8,'image',zero=True)
        self.assertEqual(s.read(0xfffffffc,4),b'\0'*4)
        with self.assertRaises(Reject):s.read(0xfffffffc,8)
        for i in range(15):s.map(0x1000+i*16,8,'heap')
        with self.assertRaises(Reject):s.map(0x3000,8,'heap')


if __name__ == '__main__':unittest.main()
