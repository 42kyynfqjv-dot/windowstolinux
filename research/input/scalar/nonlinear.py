"""Independent test-only scalar expression experiment; no admission authority."""
from dataclasses import dataclass
from model import Expr, State, REGS, U32
M = 1 << 32

@dataclass(frozen=True)
class Node:
    op: str
    left: object
    right: object
    def __post_init__(self):
        if self.op not in ('add', 'mul') or not all(type(x) in (Expr, Node) for x in (self.left, self.right)):
            raise ValueError('scalar operands required')
        size, depth = cost(self)
        if size > 63 or depth > 12:
            raise ValueError('expression resource cap')

def cost(e):
    if type(e) is Expr:return 1, 1
    if type(e) is not Node:raise ValueError('scalar required')
    a, ad = cost(e.left);b, bd = cost(e.right)
    return 1+a+b, 1+max(ad, bd)

def bounds(e, ranges):
    if type(ranges) is not tuple or len(ranges)!=3 or any(type(r) is not tuple or len(r)!=2 or any(type(v) is not int for v in r) or not 0<=r[0]<=r[1]<=U32 for r in ranges):
        raise ValueError('range domain')
    if type(e) is Expr:return e.bounds(ranges)
    if type(e) is not Node:raise ValueError('unknown scalar')
    a,b=bounds(e.left,ranges);c,d=bounds(e.right,ranges)
    lo,hi=(a+c,b+d) if e.op=='add' else (a*c,b*d)
    # Cartesian enclosure remains sound for correlated/aliased operands.
    return (lo%M,hi%M) if lo//M==hi//M else (0,U32)

def portable(e, ranges):
    if bounds(e,ranges)[1]>255:raise ValueError('unproved portable result')
    return True

def signed(v):return v if v < 1<<31 else v-M

def imul(a,b):
    if any(type(x) is not int or not 0<=x<=U32 for x in (a,b)):raise ValueError('operand width')
    full=signed(a)*signed(b);low=full%M;overflow=full!=signed(low)
    return low,dict(cf=overflow,of=overflow,zf=None,sf=None,pf=None,af=None)

class Machine(State):
    def read(self,r):
        if r not in REGS or type(self.registers[r]) not in (Expr,Node):raise ValueError('unknown/pointer scalar')
        return self.registers[r]
    def write(self,r,e,width=32):
        if r not in REGS or width!=32 or type(e) not in (Expr,Node):raise ValueError('scalar/full destination required')
        self.registers[r]=e
    def binary(self,d,s,op):
        # Both immutable operands are captured before destination changes.
        result=Node(op,self.read(d),self.read(s))
        self.write(d,result);self.predicate=None
    def compare(self,r,k,width=32):
        if type(self.read(r)) is not Expr:raise ValueError('nonlinear predicate not supported')
        super().compare(r,k,width)
    def fork(self):
        return Machine(self.ranges,dict(self.registers),self.predicate,self.owner,self.initialized,self.live)
    def arithmetic(self,d,constant):
        if type(constant) is not int or not 0<=constant<=U32:raise ValueError('immediate width')
        e=self.read(d)
        self.write(d,e.affine(Expr(),0,constant) if type(e) is Expr else Node('add',e,Expr(constant)))
        self.predicate=None
    def lea(self,d,a,b,scale,disp=0):
        if type(self.read(a)) is not Expr or type(self.read(b)) is not Expr:raise ValueError('nonlinear LEA outside first contract')
        super().lea(d,a,b,scale,disp)
    def movzx16(self,d,s):
        if type(self.read(s)) is not Expr:raise ValueError('nonlinear projection not proved')
        super().movzx16(d,s)
