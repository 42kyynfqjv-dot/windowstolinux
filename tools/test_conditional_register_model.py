import unittest
from conditional_register_model import Model, Pointer, Unknown, decode

TRACE=bytes.fromhex('8b442408 ba01000000 8b4c2404 3bc8 0f4dc2 03c1 c3')

class Contract(unittest.TestCase):
    def test_exact_observed_forms(self):
        self.assertEqual(decode(TRACE),['eax_arg2','edx_one','ecx_arg1','cmp','cmov','add','ret'])
        for h in ['668b442408','8b442409','8b442404','ba02000000','8b542404',
                  '3bc1','0f4cc2','0f4d02','03c2','f003c1','0f4d','8b4424']:
            with self.subTest(h=h),self.assertRaises(ValueError):decode(bytes.fromhex(h))
    def test_signed_cmp_literal_table(self):
        # CF,ZF,SF,OF expected independently; CMP is ECX minus EAX.
        for a,b,flags,ge in [
            (0,0,(False,True,False,False),True),
            (0,1,(True,False,True,False),False),
            (0xffffffff,0,(False,False,True,False),False),
            (0,0xffffffff,(True,False,False,False),True),
            (0x80000000,0x7fffffff,(False,False,False,True),False),
            (0x7fffffff,0x80000000,(True,False,True,True),True),
            (0x80000000,0x80000000,(False,True,False,False),True)]:
            m=Model();m.regs.update(ecx=a,eax=b,edx=17);before=dict(m.regs)
            m.step('cmp');self.assertEqual(m.regs,before);self.assertEqual(m.flags,flags)
            m.step('cmov');self.assertEqual(m.regs['eax'],17 if ge else b)
            self.assertEqual(m.flags,flags)
    def test_helper_expected_values(self):
        # Fixed expectations, not calculated using arithmetic()/signed() oracle.
        for a,b,result in [(7,5,8),(3,4,7),(0,0,1),(0xffffffff,0,0xffffffff),
                           (0x80000000,0x7fffffff,0xffffffff),(0x7fffffff,0x80000000,0x80000000)]:
            m=Model();m.call([a,b])
            for op in decode(TRACE):m.step(op)
            self.assertEqual(m.regs['eax'],result);self.assertEqual(m.frames,[0])
    def test_add_literal_boundaries(self):
        for a,b,result,flags in [(0xffffffff,1,0,(True,True,False,False)),
          (0x7fffffff,1,0x80000000,(False,False,True,True)),
          (0x80000000,0x80000000,0,(True,True,False,True))]:
            m=Model();m.regs.update(eax=a,ecx=b);m.step('add')
            self.assertEqual((m.regs['eax'],m.flags),(result,flags))
    def test_cmov_rejects_unknown_and_pointer_even_false(self):
        for value in [Unknown('entry'),Pointer(object(),0x2060)]:
            for name in ['eax','edx']:
                m=Model();m.regs.update(eax=7,edx=1);m.regs[name]=value
                m.flags=(False,False,True,False);before=dict(m.regs)
                with self.assertRaises(ValueError):m.step('cmov')
                self.assertEqual(m.regs,before)
        m=Model();m.regs.update(eax=1,edx=1)
        with self.assertRaises(ValueError):m.step('cmov')
    def test_argument_provenance(self):
        for word in [('saved',0,7),('return',0,7),('data',99,7),
                     ('data',0,Pointer(object(),0x2060)),('data',0,Unknown('arg'))]:
            m=Model();m.call([3,4]);m.words[-3]=word
            with self.assertRaises(ValueError):m.step('eax_arg2')
        m=Model();m.call([])
        with self.assertRaises(ValueError):m.step('eax_arg2')
        m=Model();m.call([3,4]);m.words.append(('data',1,0))
        with self.assertRaises(ValueError):m.step('ecx_arg1')
    def test_external_clobber_and_reload(self):
        m=Model();m.call([3,4]);m.regs.update(eax=4,ecx=3,edx=1);m.step('cmp')
        m.external_write_success(6)
        self.assertIsNone(m.flags);self.assertIsInstance(m.regs['ecx'],Unknown)
        self.assertIsInstance(m.regs['edx'],Unknown)
        old_ecx,old_edx=m.regs['ecx'],m.regs['edx']
        self.assertIsNot(old_ecx.origin,old_edx.origin)
        m.external_write_success(6)
        self.assertIsNot(m.regs['ecx'].origin,old_ecx.origin)
        self.assertIsNot(m.regs['edx'].origin,old_edx.origin)
        for op in ['cmp','add','cmov']:
            with self.assertRaises(ValueError):m.step(op)
        for op in decode(TRACE):m.step(op)
        self.assertEqual(m.regs['eax'],7)
    def test_internal_effects_and_context_separation(self):
        m=Model();self.assertIs(m.fork().regs['ecx'],m.regs['ecx'])
        m.regs.update(eax=10,ecx=20,edx=30);m.flags=(False,False,False,False)
        m.call([1,2]);self.assertEqual(m.regs['ecx'],20)
        outer=m.fork();m.call([7,5])
        for op in decode(TRACE):m.step(op)
        self.assertEqual(m.regs,dict(eax=8,ecx=7,edx=1))
        self.assertEqual(outer.regs,dict(eax=10,ecx=20,edx=30))
        # Production must retain these distinct paths, never merge into guessed state.
        self.assertNotEqual(m.regs,outer.regs)
        m.external_write_success(5);outer.step('cmp')
        with self.assertRaises(ValueError):m.step('cmp')

    def test_mov_and_cmov_preserve_known_and_unknown_flags(self):
        for flags in [None,(True,False,False,True),(False,True,False,False)]:
            m=Model();m.call([7,5]);m.flags=flags
            for op in ['eax_arg2','edx_one','ecx_arg1']:
                m.step(op);self.assertEqual(m.flags,flags)
            before=dict(m.regs)
            m.call([1,2]);self.assertEqual(m.flags,flags);self.assertEqual(m.regs,before)
            if flags is None:
                with self.assertRaises(ValueError):m.step('cmov')
            else:
                m.step('cmov');self.assertEqual(m.flags,flags)

    def test_cmp_and_add_scalar_exclusions_are_atomic(self):
        for op in ['cmp','add']:
            for name in ['eax','ecx']:
                for value in [Unknown('entry'),Pointer(object(),0x2060)]:
                    m=Model();m.regs.update(eax=7,ecx=5);m.regs[name]=value
                    m.flags=(True,False,True,False)
                    before=dict(m.regs);flags=m.flags
                    with self.assertRaises(ValueError):m.step(op)
                    self.assertEqual(m.regs,before);self.assertEqual(m.flags,flags)
