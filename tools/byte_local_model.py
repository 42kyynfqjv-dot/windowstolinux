"""SUB-532 independent decoded-action model; no production or previous model imports."""
from copy import deepcopy

class Rejected(Exception): pass
def require(ok, message):
    if not ok: raise Rejected(message)
def scalar(value):
    require(isinstance(value,tuple) and len(value)==4 and all(x is None or type(x) is int and 0<=x<=255 for x in value),'scalar bytes')
    return value
def word(value):
    scalar(value);require(None not in value,'unknown full register')
    return sum(b<<(8*i) for i,b in enumerate(value))
def bytes32(n):return tuple((n>>(8*i))&255 for i in range(4))

class Model:
    def __init__(self):
        self.reg={'eax':(None,)*4,'ecx':(None,)*4}
        self.flags={k:None for k in ('cf','zf','sf','of')}
        self.stack=[('entry',0)]
        self.frames=[(0,0,None)] # owner, protected index, allocation token
        self.serial=0;self.steps=0;self.done=False
    def boundary(self):
        owner,at,_=self.frames[-1]
        require(at<len(self.stack) and self.stack[at]==(('entry',0) if len(self.frames)==1 else ('return',owner)),'protected boundary')
        return owner,at
    def window(self):
        owner,at=self.boundary();token=self.frames[-1][2]
        require(token is not None and len(self.stack)==at+2,'byte allocation shape')
        slot=self.stack[-1]
        require(len(slot)==4 and slot[:3]==('bytes',owner,token),'byte ownership')
        scalar(slot[3]);return slot[3]
    def byte(self,offset):
        require(offset in (0,1),'exact byte offset')
        value=self.window()[offset];require(value is not None,'unknown byte');return value
    def step(self,op,*args):
        candidate=deepcopy(self);result=candidate.apply(op,*args)
        self.__dict__=candidate.__dict__;return result
    def apply(self,op,*args):
        require(not self.done and self.steps<1024,'terminal/step limit')
        owner,at=self.boundary();token=self.frames[-1][2]
        if op=='push_ecx':
            require(token is None and len(self.stack)==at+1,'allocation shape')
            require(len(self.stack)<129,'stack limit');value=scalar(self.reg['ecx'])
            self.stack.append(('bytes',owner,self.steps+1,value));self.frames[-1]=(owner,at,self.steps+1)
        elif op in ('store','store_al'):
            offset=args[0];require(offset in (0,1) and (op!='store_al' or offset==1),'exact store')
            value=args[1] if op=='store' else scalar(self.reg['eax'])[0]
            require(type(value) is int and 0<=value<=255,'unknown/scalar byte source')
            cells=list(self.window());cells[offset]=value
            self.stack[-1]=('bytes',owner,token,tuple(cells))
        elif op=='movzx':
            reg,offset=args;require((reg,offset) in (('eax',0),('eax',1),('ecx',1)),'exact load')
            self.reg[reg]=(self.byte(offset),0,0,0)
        elif op=='inc_al':
            old=scalar(self.reg['eax']);require(old[0] is not None,'unknown AL')
            value=(old[0]+1)&255;self.reg['eax']=(value,)+old[1:]
            self.flags.update(zf=value==0,sf=value>=128,of=old[0]==127)
        elif op=='add':
            a,b=word(self.reg['eax']),word(self.reg['ecx']);total=a+b;value=total&0xffffffff
            signed=lambda x:x if x<0x80000000 else x-0x100000000
            self.reg['eax']=bytes32(value)
            self.flags=dict(cf=total>0xffffffff,zf=value==0,sf=value>=0x80000000,of=not -2147483648<=signed(a)+signed(b)<=2147483647)
        elif op=='pop_ecx':
            self.reg['ecx']=self.window();self.stack.pop();self.frames[-1]=(owner,at,None)
        elif op=='flag':
            require(args[0] in self.flags and self.flags[args[0]] is not None,'unknown flag')
        elif op=='call':
            if token is not None:self.window()
            require(len(self.frames)<=32 and len(self.stack)<129,'call limit')
            self.serial+=1;self.frames.append((self.serial,len(self.stack),None));self.stack.append(('return',self.serial))
        elif op=='ret':
            require(token is None and len(self.stack)==at+1,'return balance')
            value=word(self.reg['eax'])
            if len(self.frames)==1:require(value<=255,'exit range');self.done=True
            else:self.frames.pop();self.stack.pop()
        else:raise Rejected('unsupported action')
        self.steps+=1
        return word(self.reg['eax']) if self.done else None
