import unittest,itertools
from model import State,Expr,api_states,joined_read,concrete_cmp,U32,REGS
class Scalar(unittest.TestCase):
    def test_register_permutations_and_guard_orders(self):
        # Six assignments, both digit orders: symbolic full ranges, not sample inputs.
        for length,first,temp in itertools.permutations(REGS):
            for order in [(0,2),(2,0)]:
                s=api_states()[2];s.mov(length,'eax')
                for offset in order:
                    s.load(first,s.owner,offset)
                    s.lea(temp,first,first,0,-48)
                    s.compare(temp,9,16)
                    s=s.branch('be')[0]
                s.load(first,s.owner,0);s.movzx16(first,first)
                s.load(temp,s.owner,2);s.movzx16(temp,temp)
                s.lea(length,first,first,4);s.lea(length,temp,length,2,-528)
                self.assertEqual(s.read(length).bounds(s.ranges),(0,99))
    def test_result_classes_and_reordered_size_guards(self):
        for register in REGS:
            for order in [('zero','large','short'),('large','short','zero')]:
                for original in api_states():
                    s=original.fork();s.mov(register,'eax');states=[s]
                    for guard in order:
                        next_states=[]
                        for s in states:
                            k={'zero':0,'large':65,'short':2}[guard];s.compare(register,k)
                            next_states+=s.branch('ne' if guard=='zero' else 'be')
                        states=next_states
                    self.assertEqual(len(states),1 if original.ranges[2] in [(1,1),(2,2)] else 0)
                    for s in states:
                        self.assertIn(s.ranges[2],[(1,1),(2,2)])
                        s.load('edx',s.owner,0)
    def test_modular_digit_preimage_all_word_values(self):
        s=State();s.write('ecx',Expr.symbol(0).affine(Expr(),0,-48));s.compare('ecx',9,16)
        valid=s.branch('be');invalid=s.branch('a')
        self.assertEqual([x.ranges[0] for x in valid],[(48,57)])
        self.assertEqual([x.ranges[0] for x in invalid],[(0,47),(58,65535)])
        for n in range(65536):self.assertEqual(any(lo<=n<=hi for lo,hi in [x.ranges[0] for x in valid]),48<=n<=57)
    def test_alias_projection_known_bits_and_partial_write_rejection(self):
        s=api_states()[2];s.load('eax',s.owner,0);self.assertEqual(s.read('eax').bounds(s.ranges),(0,U32))
        s.movzx16('ecx','eax');self.assertEqual(s.read('ecx').known_bits(s.ranges),(0xffff0000,0))
        with self.assertRaises(ValueError):s.write('eax',Expr(7),16)
        with self.assertRaises(ValueError):s.write('ah',Expr(7))
        with self.assertRaises(ValueError):s.write('eax',object())
        with self.assertRaises(ValueError):Expr.symbol(2).project16()
    def test_flags_snapshot_clobber_and_width_boundaries(self):
        s=State();s.write('eax',Expr.symbol(0));s.compare('eax',57,16);s.write('eax',Expr(0))
        self.assertEqual(s.branch('be')[0].ranges[0],(0,57)) # old expression snapshot
        s.arithmetic('eax',1)
        with self.assertRaises(ValueError):s.branch('be')
        s.clobber_volatile_registers()
        with self.assertRaises(ValueError):s.read('eax')
        for a,b,w,expected in [(0,1,16,(1,0,1,0)),(0x8000,1,16,(0,0,0,1)),(0x7fff,0xffff,16,(1,0,1,1)),(0x80000000,1,32,(0,0,0,1)),(9,9,32,(0,1,0,0))]:
            self.assertEqual(tuple(concrete_cmp(a,b,w).values()),expected)
    def test_owned_initialization_joins_and_stale_capabilities(self):
        failed,one,two,*_=api_states()
        for s,off in [(failed,0),(one,2),(two,3),(two,4)]:
            with self.assertRaises(ValueError):s.load('eax',s.owner,off)
        with self.assertRaises(ValueError):two.load('eax',one.owner,0)
        other=two.fork();other.initialized=4
        with self.assertRaises(ValueError):joined_read([two,other],two.owner,2)
        token=two.owner;two.release()
        with self.assertRaises(ValueError):two.load('eax',token,0)
    def test_wrap_bounds_and_noninvertible_predicates(self):
        s=State(ranges=((48,48),(55,55),(2,2)))
        first=Expr.symbol(0).affine(Expr(),0,-48);mid=first.affine(first,4,-24)
        self.assertEqual(mid.bounds(s.ranges),(0xffffffe8,0xffffffe8))
        self.assertEqual(Expr.symbol(1).affine(mid,2).bounds(s.ranges),(7,7))
        e=Expr.symbol(0).affine(Expr(),0,-1);self.assertEqual(e.bounds(((0,1),(0,0),(0,0))),(0,U32))
        s.write('eax',Expr.symbol(0).affine(Expr.symbol(1)));s.compare('eax',9)
        with self.assertRaises(ValueError):s.branch('be')
        s.write('eax',Expr.symbol(2));s.ranges=((0,65535),(0,65535),(0,U32));s.compare('eax',9,16)
        with self.assertRaises(ValueError):s.branch('be')
    def test_invalid_model_values_reject(self):
        for value in [-1,U32+1,1.5,True]:
            with self.assertRaises(ValueError):Expr(value)
        with self.assertRaises(ValueError):Expr(0,[1,0,0])
        s=State()
        with self.assertRaises(ValueError):s.mov('eax','ecx')
        with self.assertRaises(ValueError):s.compare('eax',0,8)
        with self.assertRaises(ValueError):joined_read([],s.owner,0)
if __name__=='__main__':unittest.main()
