"""Independent test-only borrow/call ownership model; no production authority."""
from dataclasses import dataclass

@dataclass(frozen=True)
class Borrow:
    owner: object
    generation: int
    offset: int = 0

@dataclass(frozen=True)
class Frame:
    identity: int
    target: int
    continuation: int
    stack: tuple
    borrowed: tuple
    saved: object

class State:
    def __init__(self, initialized=0, length=(0,0), entry=0x1040):
        if type(entry) is not int or entry<0:raise ValueError('entry')
        self.entry=entry
        if type(initialized) is not int or initialized not in (0,4,6):raise ValueError('API initialization class')
        if type(length) is not tuple or len(length)!=2 or any(type(x) is not int for x in length) or not 0<=length[0]<=length[1]<=0xffffffff:raise ValueError('length')
        # Result/initialization pair is constrained, never independently supplied facts.
        if (initialized==4 and length!=(1,1)) or (initialized==6 and length!=(2,2)) or (initialized==0 and not (length==(0,0) or length[0]>=4)):raise ValueError('inconsistent API class')
        self.owner=object();self.generation=0;self.live=True;self.initialized=initialized;self.length=length
        self.stack=[('entry',0),('local',4),('local',0)]
        self.frames=[];self.next_frame=1;self.esi=object();self.regs={};self.blocked=False
    @property
    def current(self):return self.frames[-1].identity if self.frames else 0
    def fork(self):
        s=object.__new__(State);s.__dict__=dict(self.__dict__);s.stack=list(self.stack);s.frames=list(self.frames);s.regs=dict(self.regs);return s
    def check(self,cap):
        if self.blocked or not self.live or type(cap) is not Borrow or cap.owner is not self.owner or cap.generation!=self.generation:raise ValueError('stale/foreign/unknown capability')
        if type(cap.offset) is not int or not 0<=cap.offset<=8:raise ValueError('capability offset')
        if self.frames and cap not in self.frames[-1].borrowed:raise ValueError('not borrowed in current frame')
    def buffer(self,esp_offset):
        if self.frames or type(esp_offset) is not int or esp_offset<0 or esp_offset%4:raise ValueError('local address form')
        index=len(self.stack)-1-esp_offset//4
        if index<0 or self.stack[index]!=('local',0):raise ValueError('not allocation base')
        cap=Borrow(self.owner,self.generation);self.check(cap);return cap
    def push(self,value):
        if len(self.stack)>=16:raise ValueError('stack cap')
        if type(value) is Borrow:self.check(value)
        elif value!='length' and (type(value) is not int or not 0<=value<=0xffffffff):raise ValueError('argument type')
        self.stack.append(('arg',self.current,value))
    def call(self,target,continuation):
        if type(target) is not int or type(continuation) is not int or target<0 or continuation<0:raise ValueError('target')
        if self.blocked or len(self.frames)>=4 or len(self.stack)>=16 or target in [self.entry]+[f.target for f in self.frames]:raise ValueError('cycle/depth/stack/effect')
        args=[]
        for word in reversed(self.stack):
            if word[0]!='arg' or word[1]!=self.current:break
            if type(word[2]) is Borrow:self.check(word[2]);args.append(word[2])
        f=Frame(self.next_frame,target,continuation,tuple(self.stack),tuple(args),self.esi);self.next_frame+=1
        self.frames.append(f);self.stack.append(('return',f.identity,continuation))
    def argument(self,offset):
        if not self.frames or offset not in (4,8):raise ValueError('argument offset')
        f=self.frames[-1];index=len(self.stack)-1-offset//4
        if tuple(self.stack)!=f.stack+(('return',f.identity,f.continuation),) or index<0:raise ValueError('argument stack shape')
        word=self.stack[index]
        parent=self.frames[-2].identity if len(self.frames)>1 else 0
        if word[0]!='arg' or word[1]!=parent:raise ValueError('protected/nonargument')
        return word[2]
    def read_word(self,cap,displacement):
        self.check(cap)
        if displacement not in (0,2):raise ValueError('address form')
        offset=cap.offset+displacement
        if offset not in (0,2) or offset+2>self.initialized:raise ValueError('complete initialized WORD')
        return ('unit',offset//2) # symbolic, never an observed character
    def load_word(self,destination,source,displacement):
        result=self.read_word(self.regs.get(source),displacement)
        self.regs[destination]=result
    def refine_length(self,value):
        if type(value) is not int or not self.length[0]<=value<=self.length[1]:raise ValueError('infeasible guard')
        child=self.fork();child.length=(value,value);return child
    def ret(self,result):
        if not self.frames or type(result) is Borrow or self.blocked:raise ValueError('return result/context')
        f=self.frames[-1]
        if tuple(self.stack)!=f.stack+(('return',f.identity,f.continuation),) or self.esi is not f.saved:raise ValueError('return/stack/preserved register')
        self.stack.pop();self.frames.pop();self.regs={'eax':result};return f.continuation
    def cleanup_arguments(self):
        if len(self.stack)<2 or any(w[0]!='arg' or w[1]!=self.current for w in self.stack[-2:]):raise ValueError('argument cleanup authority')
        del self.stack[-2:]
    def cleanup_locals(self):
        if self.frames or self.stack!=[('entry',0),('local',4),('local',0)] or self.blocked:raise ValueError('local cleanup authority')
        del self.stack[-2:];self.live=False;self.initialized=0;self.generation+=1
    def unknown_external_effect(self):
        self.blocked=True;self.initialized=0;self.generation+=1
