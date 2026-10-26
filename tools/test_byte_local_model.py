import unittest
from copy import deepcopy
from byte_local_model import Model,Rejected,word

class ByteLocals(unittest.TestCase):
    def rejects(self,m,op,*args):
        before=deepcopy(m.__dict__)
        with self.assertRaises(Rejected):m.step(op,*args)
        self.assertEqual(m.__dict__,before)
    def test_compiler_literal_trace(self):
        m=Model();m.step('push_ecx');m.step('store',0,65);m.step('store',1,66)
        self.assertEqual(m.stack,[('entry',0),('bytes',0,1,(65,66,None,None))])
        m.step('movzx','eax',1);m.step('inc_al');m.step('store_al',1)
        m.step('movzx','ecx',1);m.step('movzx','eax',0);m.step('add')
        flags=dict(m.flags);m.step('pop_ecx')
        self.assertEqual(m.reg['ecx'],(65,67,None,None));self.assertEqual(m.flags,flags)
        self.assertEqual(m.step('ret'),132);self.assertEqual(m.steps,11)
    def test_inc_literal_boundaries_and_unknown_upper_bytes(self):
        for old,new,z,s,o in [(0,1,False,False,False),(127,128,False,True,True),(128,129,False,True,False),(255,0,True,False,False)]:
            for carry in (None,False,True):
                m=Model();m.reg['eax']=(old,None,0xab,0xcd);m.flags['cf']=carry;m.step('inc_al')
                self.assertEqual(m.reg['eax'],(new,None,0xab,0xcd))
                self.assertEqual(m.flags,dict(cf=carry,zf=z,sf=s,of=o))
                if carry is None:self.rejects(m,'flag','cf')
                m.step('flag','zf');self.rejects(m,'add');self.rejects(m,'ret')
        self.rejects(Model(),'inc_al')
    def test_byte_overwrite_zero_extension_and_pop_partial_value(self):
        m=Model();m.reg['ecx']=(0x11,0x22,0x33,0x44);m.flags=dict(cf=True,zf=False,sf=True,of=False)
        flags=dict(m.flags);m.step('push_ecx');m.step('store',1,255);m.step('store',1,67)
        self.assertEqual(m.window(),(0x11,67,0x33,0x44));m.reg['eax']=(None,255,None,2)
        m.step('movzx','eax',1);self.assertEqual(m.reg['eax'],(67,0,0,0));m.step('pop_ecx')
        self.assertEqual(word(m.reg['ecx']),0x44334311);self.assertEqual(m.flags,flags)
    def test_unknown_bytes_full_reads_and_exact_forms(self):
        m=Model();m.step('push_ecx');m.step('store',0,65)
        self.rejects(m,'movzx','eax',1);self.rejects(m,'store_al',1)
        for offset in (-1,2,3,4):
            self.rejects(m,'store',offset,7);self.rejects(m,'movzx','eax',offset)
        for op in ('word_load','word_store','cleanup_two','push_ecx','save','tail'):self.rejects(m,op)
        m.step('pop_ecx');self.assertEqual(m.reg['ecx'],(65,None,None,None));self.rejects(m,'add')
        self.rejects(m,'pop_ecx')
    def test_protected_foreign_mixed_tags_and_atomic_errors(self):
        for bad in [('entry',0),('return',0),('saved',0,7),('data',0,7),('local',0,1,7),('bytes',99,1,(1,2,3,4)),('bytes',0,99,(1,2,3,4)),('bytes',0,1,('pointer',2,3,4))]:
            m=Model();m.step('push_ecx');m.stack[-1]=bad
            for op,args in [('store',(0,7)),('movzx',('eax',0)),('pop_ecx',()),('call',())]:self.rejects(m,op,*args)
        m=Model();m.step('push_ecx');m.stack[0]=('return',0);self.rejects(m,'store',0,1)
        m=Model();m.reg['ecx']=('pointer',0,0,0);self.rejects(m,'push_ecx')
    def test_nested_shared_calls_and_path_initialization(self):
        m=Model();m.step('push_ecx');m.step('store',0,65);parent=deepcopy(m.stack)
        for _ in range(2):
            m.step('call');self.rejects(m,'movzx','eax',0);m.reg['ecx']=(None,)*4
            m.step('push_ecx');self.rejects(m,'movzx','eax',1);m.step('store',1,7)
            m.step('movzx','eax',1);m.step('pop_ecx');m.step('ret');self.assertEqual(m.stack,parent)
        other=deepcopy(m);m.step('store',1,9);m.step('movzx','eax',1);self.rejects(other,'movzx','eax',1)
    def test_limits_return_and_no_reused_initialization(self):
        m=Model();m.step('push_ecx');m.reg['eax']=(1,0,0,0);self.rejects(m,'ret')
        m.step('pop_ecx');m.reg['ecx']=(None,)*4;m.step('push_ecx');self.rejects(m,'movzx','eax',0)
        m.steps=1024;self.rejects(m,'pop_ecx')
        m=Model()
        for _ in range(32):m.step('call')
        self.rejects(m,'call')
        m=Model();m.reg['eax']=(0,1,0,0);self.rejects(m,'ret')
        m.reg['eax']=(0,0,0,0);m.step('ret');self.rejects(m,'push_ecx')
    def test_scalar_add_independent_boundary_table(self):
        for a,b,result,c,z,s,o in [(0xffffffff,1,0,True,True,False,False),(0x7fffffff,1,0x80000000,False,False,True,True),(0x80000000,0x80000000,0,True,True,False,True)]:
            m=Model();m.reg['eax']=tuple(a.to_bytes(4,'little'));m.reg['ecx']=tuple(b.to_bytes(4,'little'));m.step('add')
            self.assertEqual(word(m.reg['eax']),result);self.assertEqual(m.flags,dict(cf=c,zf=z,sf=s,of=o))
if __name__=='__main__':unittest.main()
