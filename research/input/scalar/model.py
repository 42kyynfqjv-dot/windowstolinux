"""Independent test-only bounded scalar semantics; no production authority."""
from dataclasses import dataclass, field
U32=(1<<32)-1
REGS=('eax','ecx','edx')
@dataclass(frozen=True)
class Expr:
    c:int=0
    coefficients:tuple=(0,0,0) # two UTF16 units, API result
    def __post_init__(self):
        if type(self.c) is not int or not 0<=self.c<=U32 or type(self.coefficients) is not tuple or len(self.coefficients)!=3 or any(type(x) is not int or not 0<=x<=U32 for x in self.coefficients):raise ValueError('expression width')
    @staticmethod
    def symbol(i):
        if i not in (0,1,2):raise ValueError('symbol')
        a=[0,0,0];a[i]=1;return Expr(0,tuple(a))
    def affine(self,other,scale=1,displacement=0):
        if not isinstance(other,Expr):raise ValueError('scalar required')
        return Expr((self.c+other.c*scale+displacement)&U32,tuple((a+b*scale)&U32 for a,b in zip(self.coefficients,other.coefficients)))
    def bounds(self,ranges):
        signed=lambda x:x if x<1<<31 else x-(1<<32)
        lo=hi=signed(self.c)
        for k,(a,b) in zip(self.coefficients,ranges):
            k=signed(k);lo+=min(k*a,k*b);hi+=max(k*a,k*b)
        return (lo&U32,hi&U32) if lo//(1<<32)==hi//(1<<32) else (0,U32)
    def project16(self):
        a=tuple(x&65535 for x in self.coefficients)
        if self.c&65535 or a[2] or sum(a)!=1:raise ValueError('projection not proved')
        return Expr(0,a)
    def known_bits(self,ranges):
        lo,hi=self.bounds(ranges);unknown=(1<<(lo^hi).bit_length())-1
        mask=U32^unknown;return mask,lo&mask
@dataclass
class State:
    ranges:tuple=((0,65535),(0,65535),(0,U32))
    registers:dict=field(default_factory=lambda:{r:None for r in REGS})
    predicate:object=None
    owner:object=field(default_factory=object)
    initialized:int=0
    live:bool=True
    def fork(self):
        # Immutable expression snapshots; preserve capability identity, copy register map.
        return State(self.ranges,dict(self.registers),self.predicate,self.owner,self.initialized,self.live)
    def read(self,r):
        if r not in REGS or not isinstance(self.registers[r],Expr):raise ValueError('unknown/non-scalar register')
        return self.registers[r]
    def write(self,r,e,width=32):
        if r not in REGS or width!=32 or not isinstance(e,Expr):raise ValueError('unsupported destination/partial write')
        self.registers[r]=e
    def mov(self,d,s):self.write(d,self.read(s))
    def lea(self,d,a,b,scale,disp=0):self.write(d,self.read(a).affine(self.read(b),scale,disp))
    def arithmetic(self,d,constant):
        self.write(d,self.read(d).affine(Expr(),0,constant));self.predicate=None
    def movzx16(self,d,s):self.write(d,self.read(s).project16())
    def compare(self,r,k,width=32):
        if width not in (16,32) or type(k) is not int or not 0<=k<1<<width:raise ValueError('compare width')
        self.predicate=(self.read(r),width,k)
    def branch(self,condition,taken=True):
        if self.predicate is None or condition not in ('ne','be','a'):raise ValueError('unknown/unsupported flags')
        e,w,k=self.predicate;m=1<<w;a=tuple(x%(m) for x in e.coefficients)
        if sum(x!=0 for x in a)!=1 or 1 not in a:raise ValueError('predicate not invertible in domain')
        i=a.index(1)
        if self.ranges[i][1]>=m:raise ValueError('truncation lacks proof')
        if condition=='ne':desired=[(0,k-1),(k+1,m-1)] if taken else [(k,k)]
        else:desired=[(0,k)] if (condition=='be')==taken else [(k+1,m-1)]
        out=[]
        for lo,hi in desired:
            if lo>hi:continue
            start=(lo-e.c)%m;end=(hi-e.c)%m
            for lo,hi in ([(start,end)] if start<=end else [(0,end),(start,m-1)]):
                lo=max(lo,self.ranges[i][0]);hi=min(hi,self.ranges[i][1])
                if lo<=hi:
                    child=self.fork();rr=list(child.ranges);rr[i]=(lo,hi);child.ranges=tuple(rr);out.append(child)
        return out
    def load(self,d,owner,offset,width=4):
        if owner is not self.owner or not self.live or width!=4 or offset not in (0,2) or offset+width>self.initialized:raise ValueError('full owned initialized range')
        e=Expr.symbol(0).affine(Expr.symbol(1),65536) if offset==0 else Expr.symbol(1)
        self.write(d,e)
    def release(self):self.live=False;self.initialized=0
    def clobber_volatile_registers(self):
        # Register effect only: does not authorize an external call or its memory effects.
        self.registers={r:None for r in REGS};self.predicate=None

def api_states():
    out=[]
    for lo,hi,n in [(0,0,0),(1,1,4),(2,2,6),(4,65,0),(66,U32,0)]:
        s=State(ranges=((0,65535),(0,0) if lo==1 else (0,65535),(lo,hi)),initialized=n)
        s.write('eax',Expr.symbol(2));out.append(s)
    return out

def joined_read(states,owner,offset):
    if not states:raise ValueError('empty join')
    for state in states:state.load('edx',owner,offset)

def concrete_cmp(a,b,width):
    if width not in (16,32):raise ValueError('width')
    mask=(1<<width)-1;a&=mask;b&=mask;r=(a-b)&mask;sign=1<<(width-1)
    return dict(cf=a<b,zf=r==0,sf=bool(r&sign),of=bool((a^b)&(a^r)&sign))
