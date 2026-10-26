import unittest
from model import Borrow,State

def enter(s,target=0x1000):
    cap=s.buffer(0);s.push('length');s.push(cap);s.call(target,0x1088);return cap

class BorrowTests(unittest.TestCase):
    def test_exact_stack_trace_and_distinct_cleanup(self):
        s=State(6,(2,2));s.push('length');cap=s.buffer(4);s.push(cap);s.call(0x1000,0x1088)
        self.assertEqual(s.argument(4),cap);self.assertEqual(s.argument(8),'length')
        self.assertEqual(s.read_word(cap,0),('unit',0));self.assertEqual(s.read_word(cap,2),('unit',1))
        self.assertEqual(s.ret(('scalar','answer')),0x1088)
        with self.assertRaises(ValueError):s.cleanup_locals()
        s.cleanup_arguments();s.cleanup_locals();self.assertEqual(s.stack,[('entry',0)])
    def test_nested_borrow_and_original_return_context(self):
        s=State(6,(2,2));cap=enter(s);s.push('length');s.push(cap);s.call(0x1100,0x1020)
        self.assertEqual(s.argument(4),cap);self.assertEqual(s.read_word(cap,2),('unit',1))
        self.assertEqual(s.ret(7),0x1020);s.cleanup_arguments();self.assertEqual(s.ret(7),0x1088)
    def test_shared_helper_contexts_do_not_share_initialization(self):
        good=State(6,(2,2));bad=State(0,(0,0));a=enter(good);b=enter(bad)
        self.assertEqual(good.read_word(a,0),('unit',0))
        with self.assertRaises(ValueError):bad.read_word(b,0)
        with self.assertRaises(ValueError):bad.read_word(a,0)
        # A WORD terminator is initialized in the one-character class.
        one=State(4,(1,1));cap=enter(one);self.assertEqual(one.read_word(cap,2),('unit',1))
        with self.assertRaises(ValueError):one.refine_length(2)
    def test_stale_alias_foreign_offset_and_unknown_effect(self):
        s=State(6,(2,2));cap=s.buffer(0);alias=cap;s.cleanup_locals()
        with self.assertRaises(ValueError):s.read_word(alias,0)
        s=State(6,(2,2));cap=enter(s)
        for bad in (Borrow(object(),0),Borrow(s.owner,99),Borrow(s.owner,0,7),None):
            with self.assertRaises(ValueError):s.read_word(bad,0)
        s.unknown_external_effect()
        with self.assertRaises(ValueError):s.read_word(cap,0)
        with self.assertRaises(ValueError):s.ret(0)
    def test_address_captured_before_register_overwrite(self):
        s=State(6,(2,2));cap=enter(s);s.regs['edx']=cap;s.load_word('edx','edx',2)
        self.assertEqual(s.regs['edx'],('unit',1))
        with self.assertRaises(ValueError):s.load_word('eax','edx',0)
    def test_protected_returns_arguments_and_preserved_register(self):
        for change in ('pop','esi','cleanup'):
            s=State(6,(2,2));enter(s)
            if change=='pop':s.stack.pop()
            elif change=='esi':s.esi=object()
            else:
                with self.assertRaises(ValueError):s.cleanup_arguments()
                continue
            with self.assertRaises(ValueError):s.ret(0)
        s=State(6,(2,2));cap=enter(s)
        with self.assertRaises(ValueError):s.ret(cap)
        with self.assertRaises(ValueError):s.argument(0)
    def test_forked_guards_and_invalid_initialization(self):
        s=State(6,(2,2));cap=enter(s);child=s.refine_length(2);child.unknown_external_effect()
        self.assertEqual(s.read_word(cap,2),('unit',1))
        with self.assertRaises(ValueError):child.read_word(cap,2)
        for init,length in [(6,(1,1)),(4,(2,2)),(0,(1,2)),(8,(2,2))]:
            with self.assertRaises(ValueError):State(init,length)
    def test_cycle_depth_stack_and_address_limits(self):
        s=State(6,(2,2),entry=0x9000);enter(s)
        with self.assertRaises(ValueError):s.call(0x9000,0x1020)
        with self.assertRaises(ValueError):s.call(0x1000,0x1020)
        for target in (0x1100,0x1200,0x1300):s.call(target,0x1010)
        with self.assertRaises(ValueError):s.call(0x1400,0x1010)
        s=State(6,(2,2))
        with self.assertRaises(ValueError):s.buffer(4)
        for _ in range(13):s.push(0)
        with self.assertRaises(ValueError):s.push(0)

if __name__=='__main__':unittest.main()
