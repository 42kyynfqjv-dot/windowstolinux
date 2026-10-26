"""Literal independently specified traces; no production/generator or flag oracle."""
import copy
import unittest
from local_frame_model import Model, Word


class LocalFrames(unittest.TestCase):
    def frame(self, first=7, second=5):
        m=Model();m.allocate8();m.store(0,first);m.store(4,second);return m

    def test_exact_compiler_trace_and_byte_layout(self):
        m=Model();m.allocate8()
        self.assertEqual([(w.tag,w.value) for w in m.words], [('entry',None),('local',None),('local',None)])
        m.store(0,7);m.store(4,5)
        self.assertEqual([w.value for w in m.words], [None,5,7])
        m.load4();self.assertEqual(m.eax,5);m.add0();self.assertEqual(m.eax,12)
        self.assertEqual(m.flags,(False,False,False,False))
        m.cleanup8();self.assertEqual(len(m.words),1);self.assertIsNone(m.flags)
        self.assertEqual(m.ret(),12);self.assertEqual(m.steps,7)

    def test_initialization_and_scalar_exclusions(self):
        for initialized in ((),(0,),(4,)):
            m=Model();m.allocate8()
            for offset in initialized:m.store(offset,3)
            with self.assertRaisesRegex(ValueError,'scalar'):
                m.load4();m.add0()
        for value in (None,True,-1,0x100000000,('pointer',0x2000),('unknown',1)):
            m=Model();m.allocate8();before=copy.deepcopy(m.__dict__)
            with self.assertRaises(ValueError):m.store(0,value)
            self.assertEqual(m.__dict__,before)

    def test_complete_word_bounds_and_protected_tags(self):
        for offset in (-4,1,2,3,5,8,12,0xfffffffc):
            m=self.frame();before=copy.deepcopy(m.__dict__)
            with self.assertRaises(ValueError):m.store(offset,99)
            self.assertEqual(m.__dict__,before)
        for tag,owner,allocation in [('return',0,1),('saved',0,1),('data',0,1),('local',99,1),('local',0,99)]:
            m=self.frame();m.words[-2]=Word(tag,owner,allocation,5)
            with self.assertRaisesRegex(ValueError,'ownership'):m.cleanup8()
            with self.assertRaisesRegex(ValueError,'ownership'):m.store(0,9)

    def test_flags_literal_boundary_table_and_mov_preservation(self):
        for a,b,result,flags in [(7,5,12,(False,False,False,False)),
              (0xffffffff,1,0,(True,True,False,False)),
              (0x7fffffff,1,0x80000000,(False,False,True,True)),
              (0x80000000,0x80000000,0,(True,True,False,True)),
              (0xffffffff,0,0xffffffff,(False,False,True,False))]:
            m=self.frame(b,a);m.load4();m.add0()
            self.assertEqual((m.eax,m.flags),(result,flags))
            m.store(0,2);m.load4();self.assertEqual(m.flags,flags)
            m.cleanup8()
            with self.assertRaisesRegex(ValueError,'unknown flags'):m.branch(1)
        m=Model();m.flags=(False,True,False,False);m.allocate8()
        with self.assertRaisesRegex(ValueError,'unknown flags'):m.branch(1)

    def test_nested_call_preserves_caller_locals_and_original_continuations(self):
        m=self.frame();m.call(100,50);m.allocate8();m.store(0,2);m.store(4,3)
        m.load4();m.add0();m.cleanup8();self.assertEqual(m.ret(),50)
        self.assertEqual([w.value for w in m.words],[None,5,7])
        m.load4();m.add0();m.cleanup8();self.assertEqual(m.ret(),12)
        m=self.frame();m.call(100,50)
        with self.assertRaises(ValueError):m.load4()  # Cannot borrow caller locals.

    def test_shared_calls_use_fresh_uninitialized_allocations(self):
        m=Model();m.call(100,10);m.allocate8();m.store(4,9);m.load4();m.cleanup8();self.assertEqual(m.ret(),10)
        m.call(100,20);m.allocate8()
        with self.assertRaisesRegex(ValueError,'scalar'):m.load4()

    def test_joins_keep_path_initialization_and_shape_separate(self):
        root=Model();root.allocate8();left=copy.deepcopy(root);right=copy.deepcopy(root)
        left.store(4,5);left.load4()
        with self.assertRaisesRegex(ValueError,'scalar'):right.load4()
        left.cleanup8()
        with self.assertRaisesRegex(ValueError,'unbalanced'):right.ret()
        # No union of left initialized values into right's missing write.
        self.assertIsNone(right.words[-2].value)

    def test_cleanup_return_and_reallocation_limits(self):
        m=self.frame();m.load4()
        with self.assertRaisesRegex(ValueError,'unbalanced'):m.ret()
        with self.assertRaisesRegex(ValueError,'allocation shape'):m.allocate8()
        m.cleanup8();m.allocate8()
        with self.assertRaisesRegex(ValueError,'scalar'):m.load4()
        m=Model();m.eax=12;m.esi=('pointer',1)
        with self.assertRaisesRegex(ValueError,'restoration'):m.ret()
        m=Model();m.eax=256
        with self.assertRaisesRegex(ValueError,'exit domain'):m.ret()

    def test_resource_caps_recursion_and_terminal_state(self):
        m=Model();m.steps=1024
        with self.assertRaisesRegex(ValueError,'step limit'):m.allocate8()
        m=Model()
        for target in range(1,33):m.call(target,target+100)
        with self.assertRaisesRegex(ValueError,'call/word limit'):m.call(33,0)
        m=Model();m.call(1,7)
        with self.assertRaisesRegex(ValueError,'recursive'):m.call(1,9)
        m=Model();m.eax=0;m.ret()
        with self.assertRaisesRegex(ValueError,'terminal'):m.allocate8()


if __name__=='__main__':unittest.main()
