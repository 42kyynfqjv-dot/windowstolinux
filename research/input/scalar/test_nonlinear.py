import itertools, unittest
from model import Expr, U32
from nonlinear import Node, Machine, bounds, portable, imul

class NonlinearTests(unittest.TestCase):
    def test_literal_signed_multiplication_flags(self):
        for a,b,value,overflow in [(0,0,0,False),(0xffffffff,2,0xfffffffe,False),(0x80000000,1,0x80000000,False),(0x80000000,0xffffffff,0x80000000,True),(0x7fffffff,2,0xfffffffe,True),(0xffffffff,0xffffffff,1,False),(65536,65536,0,True)]:
            result,flags=imul(a,b);self.assertEqual(result,value)
            self.assertEqual(flags,dict(cf=overflow,of=overflow,zf=None,sf=None,pf=None,af=None))
        for bad in (-1,1<<32,1.5,True):
            with self.assertRaises(ValueError):imul(bad,0)
    def test_unsigned_interval_contains_independent_products(self):
        spans=[(0,9),(48,57),(0x7ffffffe,0x80000001),(0xfffffffd,U32)]
        for a,b in itertools.product(spans,repeat=2):
            rr=(a,b,(0,0));e=Node('mul',Expr.symbol(0),Expr.symbol(1));lo,hi=bounds(e,rr)
            for x,y in itertools.product(range(a[0],a[1]+1),range(b[0],b[1]+1)):
                self.assertLessEqual(lo,(x*y)%2**32);self.assertLessEqual((x*y)%2**32,hi)
    def test_frozen_digit_range_and_all_decimal_expectations(self):
        x=Expr.symbol(0).affine(Expr(),0,0xffffffd0);y=Expr.symbol(1).affine(Expr(),0,0xffffffd0)
        e=Node('add',Node('mul',x,x),Node('mul',y,y))
        self.assertEqual(bounds(e,((48,57),(48,57),(2,2))),(0,162))
        for a,b in itertools.product(range(10),repeat=2):
            self.assertEqual(bounds(e,((48+a,48+a),(48+b,48+b),(2,2))),(a*a+b*b,)*2)
        self.assertTrue(portable(e,((48,57),(48,57),(2,2))))
        with self.assertRaises(ValueError):portable(e,((0,65535),(0,65535),(2,2)))
    def test_register_aliases_and_snapshots(self):
        for a,b,c in itertools.permutations(('eax','ecx','edx')):
            s=Machine();s.write(a,Expr.symbol(0));s.mov(b,a);old=s.read(b)
            s.binary(a,a,'mul');s.write(c,Expr(7));s.binary(a,c,'add')
            self.assertEqual(s.read(b),old);self.assertEqual(bounds(s.read(a),((3,3),(0,0),(0,0))),(16,16))
    def test_guards_survive_copies_but_arithmetic_invalidates_flags(self):
        s=Machine();s.write('eax',Expr.symbol(0).affine(Expr(),0,0xffffffd0));s.compare('eax',9,16)
        s.mov('edx','eax');s.write('eax',Expr(123))
        child=s.branch('be')[0];self.assertEqual(child.ranges[0],(48,57));self.assertIsInstance(child,Machine)
        child.binary('edx','edx','mul')
        with self.assertRaises(ValueError):child.branch('be')
        with self.assertRaises(ValueError):child.compare('edx',9)
        with self.assertRaises(ValueError):child.movzx16('eax','edx')
    def test_correlations_are_overapproximated_and_wrap_rejects(self):
        x=Expr.symbol(0);negative=x.affine(Expr(),0,0) # same symbol retained, no sampled result
        e=Node('mul',x,negative)
        self.assertEqual(bounds(e,((0,U32),(0,0),(0,0))),(0,U32))
        with self.assertRaises(ValueError):portable(e,((0,U32),(0,0),(0,0)))
        self.assertEqual(bounds(Node('mul',Expr(U32),Expr(2)),((0,0),)*3),(U32-1,U32-1))
    def test_ownership_unknown_partial_and_join_rejection(self):
        s=Machine(initialized=4);s.load('eax',s.owner,0)
        with self.assertRaises(ValueError):s.load('ecx',s.owner,2)
        with self.assertRaises(ValueError):s.load('ecx',object(),0)
        with self.assertRaises(ValueError):s.binary('eax','edx','mul')
        with self.assertRaises(ValueError):s.write('eax',Expr(),16)
        fork=s.fork();fork.release()
        for state in (s,fork):
            if not state.live:
                with self.assertRaises(ValueError):state.load('eax',state.owner,0)
        with self.assertRaises(ValueError):Node('mul',object(),Expr())
    def test_resource_caps_and_malformed_ranges(self):
        e=Expr(1)
        for _ in range(5):e=Node('mul',e,e)
        with self.assertRaises(ValueError):Node('mul',e,e)
        for rr in ([(0,1)]*3,((2,1),(0,0),(0,0)),((False,1),(0,0),(0,0))):
            with self.assertRaises(ValueError):bounds(Expr(),rr)

if __name__=='__main__':unittest.main()
