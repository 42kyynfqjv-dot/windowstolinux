"""SUB-536 test-only proof experiment. No production code or executable capability.

Reuses checked test-only image layout; new proof is structural, not observed termination.
"""
from dataclasses import dataclass
from image_read_model import need, Rejected
MASK=0xffffffff
# All code bytes except the two typed address fields. Fixed graph, not arbitrary CFG.
SKELETON=bytes.fromhex('33c0 33c9 390500000000 760f 0f1f4000 03c1 41 3b0d00000000 72f5 c3')

@dataclass(frozen=True)
class Proof:
    bound: int
    steps: int
    result: int
    image: str
    target: int

def scalar(value):
    need(type(value) is int and 0 <= value <= MASK, 'known u32 required')
    return value

def compare(a,b):
    a,b=scalar(a),scalar(b);v=(a-b)&MASK
    return (a<b,v==0,bool(v&0x80000000),bool((a^b)&(a^v)&0x80000000))

def add(a,b):
    a,b=scalar(a),scalar(b);v=(a+b)&MASK
    return v,(a+b>MASK,v==0,bool(v&0x80000000),bool(~(a^b)&(a^v)&0x80000000))

def increment(a,flags):
    a=scalar(a);v=(a+1)&MASK
    return v,(flags[0],v==0,bool(v&0x80000000),a==0x7fffffff)

def branch(kind,flags):
    if kind=='jb':
        need(flags[0] is not None,'unknown CF');return flags[0]
    need(kind=='jbe','unsupported condition')
    need(flags[0] is not None and flags[1] is not None,'unknown CF/ZF')
    return flags[0] or flags[1]

def prove(image):
    code=image.code.data[:image.code.virtual]
    need(len(code)==28,'exact complete graph extent')
    stencil=bytearray(code);stencil[6:10]=b'\0'*4;stencil[21:25]=b'\0'*4
    need(stencil==SKELETON,'unproved graph/effect')
    # Independent explicit edge arithmetic; both edges land on decoded boundaries.
    need(12+int.from_bytes(code[11:12],'little',signed=True)==27 and
         27+int.from_bytes(code[26:27],'little',signed=True)==16,'edge target')
    need(sorted((r.site,r.kind) for r in image.relocations)==
         [(image.entry+6,3),(image.entry+21,3)],'exact relocation accounting')
    targets=[]
    for offset in (6,21):
        va=int.from_bytes(code[offset:offset+4],'little')
        need(va>=image.base,'VA underflow');target=va-image.base
        image.outside(image.entry+offset,4);image.outside(target,4)
        section,data=image.locate(target,4)
        need(section.role=='writable','initialized scalar data required')
        targets.append((target,int.from_bytes(data,'little')))
    need(targets[0][0]==targets[1][0],'loop invariant bound must be same word')
    n=targets[0][1]
    # Structural induction: reset i=0; body increments i once, compares i<N,
    # sole backedge returns to the header. Rank N-i strictly decreases, no i wrap.
    steps=5 if n==0 else 6+4*n
    need(n<=254 and steps<=1024,'static iteration/step budget')
    result=n*(n-1)//2
    return Proof(n,steps,result,image.identity,targets[0][0])

def trace(proof):
    """Concrete checking AFTER structural proof; no production/runtime interpreter."""
    n=proof.bound;eax=ecx=0;steps=4;header=[];flags=compare(n,eax)
    if not branch('jbe',flags):
        steps+=1 # NOP, no memory effect
        while True:
            need(steps+4 < 1024,'runtime backstop exceeded')
            header.append((ecx,eax,n-ecx))
            eax,flags=add(eax,ecx);ecx,flags=increment(ecx,flags)
            flags=compare(ecx,n);steps+=4
            if not branch('jb',flags):break
    steps+=1
    need(steps==proof.steps and eax==proof.result,'proof/trace mismatch')
    return {'eax':eax,'ecx':ecx,'flags':flags,'steps':steps,'headers':header,'emission_allowed':False}

def eligible(proof):
    need(proof.result<=255,'portable exit domain')
    return trace(proof)
