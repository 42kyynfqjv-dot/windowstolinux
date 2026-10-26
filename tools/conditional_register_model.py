"""SUB-523 independent test-only contract model; never imported by production."""
from dataclasses import dataclass
import copy

MASK = 2**32-1
@dataclass(frozen=True)
class Unknown:
    origin: object
@dataclass(frozen=True)
class Pointer:
    image: object
    rva: int

def integer(v):
    if type(v) is not int or not 0 <= v <= MASK:
        raise ValueError('scalar required')
    return v

def signed(v):
    return v if v < 2**31 else v-2**32

def arithmetic(a, b, subtract=False):
    a, b = integer(a), integer(b)
    wide = a-b if subtract else a+b
    signed_wide = signed(a)-signed(b) if subtract else signed(a)+signed(b)
    result = wide & MASK
    # Wide integer model intentionally differs from production bitwise overflow.
    flags = (a < b if subtract else wide > MASK, result == 0,
             result >= 2**31, not -2**31 <= signed_wide < 2**31)
    return result, flags

FORMS = [(bytes.fromhex(h), op) for h, op in [
    ('8b442408','eax_arg2'), ('ba01000000','edx_one'),
    ('8b4c2404','ecx_arg1'), ('3bc8','cmp'), ('0f4dc2','cmov'),
    ('03c1','add'), ('c3','ret')]]

def decode(code):
    if not code or len(code)>64:
        raise ValueError('bounded helper')
    result=[]
    while code:
        for form, op in FORMS:
            if code.startswith(form):
                result.append(op);code=code[len(form):];break
        else:raise ValueError('unsupported or truncated form')
    return result

class Model:
    def __init__(self):
        self.regs={r:Unknown(object()) for r in ('eax','ecx','edx')}
        self.flags=None
        self.frames=[0]
        self.words=[('entry',0,None)]
        self.serial=0
    def fork(self):
        other=copy.copy(self)
        other.regs=self.regs.copy();other.words=self.words.copy();other.frames=self.frames.copy()
        return other
    def call(self, args):
        owner=self.frames[-1]
        self.words.extend(('data',owner,v) for v in reversed(args))
        self.serial+=1
        self.frames.append(self.serial)
        self.words.append(('return',self.serial,None))
        # CALL itself does not reset flags or volatile registers.
    def argument(self, ordinal):
        if len(self.frames)<2 or self.words[-1][:2]!=('return',self.frames[-1]):
            raise ValueError('argument boundary')
        index=len(self.words)-1-ordinal
        if index<0:raise ValueError('argument bounds')
        kind,owner,value=self.words[index]
        if kind!='data' or owner!=self.frames[-2]:raise ValueError('argument ownership')
        return integer(value)
    def step(self, op):
        r=self.regs
        if op=='eax_arg2':r['eax']=self.argument(2)
        elif op=='ecx_arg1':r['ecx']=self.argument(1)
        elif op=='edx_one':r['edx']=1
        elif op=='cmp':self.flags=arithmetic(r['ecx'],r['eax'],True)[1]
        elif op=='add':r['eax'],self.flags=arithmetic(r['eax'],r['ecx'])
        elif op=='cmov':
            if self.flags is None:raise ValueError('unknown flags')
            old,source=integer(r['eax']),integer(r['edx'])
            r['eax']=source if self.flags[2]==self.flags[3] else old
        elif op=='ret':
            if len(self.frames)<2 or self.words[-1][:2]!=('return',self.frames[-1]):
                raise ValueError('protected return')
            integer(r['eax']);self.words.pop();self.frames.pop()
        else:raise ValueError('unsupported operation')
    def external_write_success(self, count):
        self.regs['eax']=integer(count)
        self.regs['ecx']=Unknown(object());self.regs['edx']=Unknown(object())
        self.flags=None
