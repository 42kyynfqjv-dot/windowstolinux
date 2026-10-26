import copy
import unittest
from nested_stack_model import Model, Word, acyclic


class NestedContract(unittest.TestCase):
    def outer(self, a=7, b=5):
        m = Model()
        m.push(b); m.push(a); m.call(0x1050, 0x101b)
        return m

    def test_literal_two_push_layout_and_return_trace(self):
        m = self.outer()
        m.flags = True
        m.copy8(); m.copy8()
        self.assertEqual(m.words, [Word('entry',0,None), Word('data',0,5), Word('data',0,7),
                                  Word('return',1,0x101b), Word('data',1,5), Word('data',1,7)])
        self.assertTrue(m.flags)
        m.call(0x1040,0x105d)
        self.assertEqual([w.value for w in m.words[-3:-1]], [5,7])
        self.assertEqual(m.ret(),0x105d)
        m.cleanup2()
        self.assertIsNone(m.flags)
        m.flags = True
        self.assertTrue(m.je())
        m.store(8,3); m.store(4,12)
        before = copy.deepcopy(m.words)
        m.tail(0x1040)
        self.assertEqual(m.words,before)
        self.assertEqual(m.ret(),0x101b)
        self.assertEqual(m.words,[Word('entry',0,None),Word('data',0,3),Word('data',0,12)])
        m.cleanup2()
        self.assertEqual(m.words,[Word('entry',0,None)])

    def test_copy_is_value_not_alias(self):
        m=self.outer();m.copy8();m.copy8()
        m.words[1]=Word('data',0,99)
        self.assertEqual(m.words[-2:], [Word('data',1,5),Word('data',1,7)])
        with self.assertRaisesRegex(ValueError,'copy shape'):m.copy8()

    def test_protected_foreign_pointer_unknown_slots_reject(self):
        for word in [Word('return',0,5),Word('saved',0,5),Word('entry',0,None),
                     Word('data',99,5),Word('data',0,('pointer','image',0x2008)),Word('data',0,('unknown',9))]:
            for operation in ['copy','store','tail']:
                m=self.outer();m.words[1]=word;before=list(m.words)
                with self.assertRaises(ValueError):
                    if operation=='copy':m.copy8()
                    elif operation=='store':m.store(8,3)
                    else:m.tail(0x1040)
                self.assertEqual(m.words,before)

    def test_store_borrow_and_flag_preservation(self):
        m=self.outer();m.flags=False;m.store(8,3);m.store(4,12)
        self.assertEqual(m.words[1:3],[Word('data',0,3),Word('data',0,12)])
        self.assertFalse(m.flags)
        for offset,value in [(0,3),(12,3),(5,12),(4,13),(8,12)]:
            with self.assertRaisesRegex(ValueError,'store form'):m.store(offset,value)

    def test_unbalanced_and_saved_return_integrity(self):
        for op in ['store','tail','ret']:
            m=self.outer();m.push(42)
            with self.assertRaisesRegex(ValueError,'unbalanced'):
                {'store':lambda:m.store(8,3),'tail':lambda:m.tail(0x1040),'ret':m.ret}[op]()
        m=self.outer();m.words[-1]=Word('return',1,0x9999)
        with self.assertRaisesRegex(ValueError,'protected return'):m.copy8()
        m=self.outer();m.esi=object()
        with self.assertRaisesRegex(ValueError,'ESI'):m.tail(0x1040)
        with self.assertRaisesRegex(ValueError,'ESI'):m.ret()

    def test_unknown_untaken_paths_and_forks(self):
        m=self.outer()
        with self.assertRaisesRegex(ValueError,'unknown ZF'):m.je()
        m.flags=False;self.assertFalse(m.je())
        alternate=copy.copy(m);alternate.words=list(m.words);alternate.frames=list(m.frames)
        alternate.words[1]=Word('saved',0,5)
        with self.assertRaises(ValueError):alternate.store(8,3)
        self.assertEqual(m.words[1],Word('data',0,5))
        self.assertEqual(m.ret(),0x101b)

    def test_cycles_and_backward_acyclic_edges(self):
        acyclic({0x1000:[0x1050],0x1050:[0x1040],0x1040:[]})
        for graph in [{1:[1]},{1:[2],2:[1]},{1:[2],2:[3],3:[2]}]:
            with self.assertRaisesRegex(ValueError,'cycle'):acyclic(graph)
        m=self.outer()
        with self.assertRaisesRegex(ValueError,'recursive'):m.call(0x1050,9)
        m.tail(0x1040)
        with self.assertRaisesRegex(ValueError,'cycle'):m.tail(0x1050)

    def test_caps_and_missing_arguments(self):
        m=Model();m.call(0x1050,9)
        with self.assertRaises(ValueError):m.copy8()
        m=self.outer();m.steps=1024
        with self.assertRaisesRegex(ValueError,'step limit'):m.copy8()
        m=Model()
        for i in range(32):m.call(i,i+1)
        with self.assertRaisesRegex(ValueError,'call limit'):m.call(40,41)
        m=Model()
        for _ in range(128):m.push(0)
        with self.assertRaisesRegex(ValueError,'word limit'):m.push(0)
