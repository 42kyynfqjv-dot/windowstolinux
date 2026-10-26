"""Independent literal x86/expected-result tests through CLI and emitted ELF.

No production, old fixture-generator or prototype imports. Synthetic PE intake
cases are distinct from the unchanged Windows compiler-artifact comparison.
"""
from pathlib import Path
import struct
import subprocess
import tempfile

converter=Path('target/debug/w2l').resolve()
def h(text): return bytes.fromhex(text)
def imm(n): return struct.pack('<I',n)
A=h('83ec08'); C=h('83c408'); L=h('8b442404'); ADD=h('030424'); R=h('c3')
def s0(n):return h('c70424')+imm(n)
def s4(n):return h('c7442404')+imm(n)
def mov(n):return b'\xb8'+imm(n)
def frame(a,b):return A+s0(a)+s4(b)+L+ADD+C+R

def image(code):
    assert 0<len(code)<=512
    b=bytearray(1024)
    def u(at,n):struct.pack_into('<I',b,at,n)
    def w(at,n):struct.pack_into('<H',b,at,n)
    b[:2]=b'MZ';u(60,128);b[128:132]=b'PE\0\0'
    for at,n in [(132,0x14c),(134,1),(148,224),(150,0x102),(152,0x10b),(220,3),(222,0x8540)]:w(at,n)
    for at,n in [(156,512),(168,4096),(172,4096),(180,0x400000),(184,4096),(188,512),
                 (208,8192),(212,512),(224,0x100000),(228,4096),(232,0x100000),(236,4096),(244,16),
                 (384,len(code)),(388,4096),(392,512),(396,512),(412,0x60000020)]:u(at,n)
    b[376:384]=b'.code\0\0\0';b[512:512+len(code)]=code
    return b

def call(pc,target):return b'\xe8'+struct.pack('<i',target-pc-5)
# Literal arithmetic answers, including wrap; model/production is never an oracle.
positive=[('sum',frame(7,5),12),('wrap',frame(0xffffffff,1),0),('max',frame(200,55),255),
    ('store12-local',frame(3,12),15),('unread-uninitialized',A+mov(9)+C+R,9),
    ('reallocate',A+s4(99)+C+A+s4(42)+L+C+R,42)]
outer=A+s0(7)+s4(5)
outer+=call(len(outer),len(outer)+5+len(L+ADD+C+R))+L+ADD+C+R
positive.append(('nested',outer+frame(1,2),12))
main=call(0,11)+call(5,11)+R
positive.append(('shared',main+frame(6,8),14))
main=h('6a01 6a02')+call(4,13)+C+R
positive.append(('data-cleanup',main+mov(42)+R,42))
# Addition sets ZF, MOV preserves it; two independently initialized successors.
flags=A+s0(0xffffffff)+s4(1)+L+ADD+h('7409')+mov(11)+C+R+mov(22)+C+R
positive.append(('flags',flags,22))
negative=[('noalloc-load',L+R),('noalloc-store',s0(1)+R),('uninit4',A+s0(7)+L+C+R),
    ('uninit0',A+s4(5)+L+ADD+C+R),('doublealloc',A+A+mov(1)+C+R),
    ('live-return',A+mov(1)+R),('live-push',A+h('6a01')+C+mov(1)+R),
    ('live-save',A+h('56')+C+mov(1)+R),('pending-data',h('6a01')+A+mov(1)+C+R),
    ('unknown-after-alloc',A+h('7400')+mov(1)+C+R),
    ('unknown-after-cleanup',frame(7,5)[:-1]+h('7400')+R),
    ('fresh-uninit',A+s4(7)+C+A+L+C+R),('partial-cleanup',A+h('83c404')+mov(1)+R),
    ('wide-exit',frame(255,1)),('unknown-eax',A+s0(1)+ADD+C+R),
    ('incomplete-caller-pair',h('6a01')+C+mov(1)+R),
    ('saved-cleanup',h('56 6a01')+C+mov(1)+R)]
# Taken invalid path and untaken invalid path must both reject independently.
negative.append(('taken-uninit',A+h('33c0 7408')+s4(7)+L+C+R))
negative.append(('untaken-uninit',A+h('33c0 7508')+s4(7)+L+C+R))
# Callee cannot reinterpret suspended caller Local words as Data arguments.
main=A+s0(7)+s4(5);main+=call(len(main),len(main)+5+len(C+R))+C+R
negative.append(('callee-borrows-locals',main+L+R))
for index,form in enumerate([h('83ec04'),h('81ec08000000'),h('8b442408'),h('8b0424'),h('89442404'),
    h('c644240407'),h('c744240207000000'),h('c744240807000000'),h('030424')[:2]]):
    negative.append(('form-'+str(index),A+form+C+mov(1)+R))
for prefix in ['66','67','f0','f2','f3','2e','3e','26','36','64','65']:
    for index in range(6):
        forms=[A,s0(7),s4(5),L,ADD,C,R]
        forms[index]=h(prefix)+forms[index]
        negative.append(('prefix-'+prefix+'-'+str(index),b''.join(forms)))
with tempfile.TemporaryDirectory() as temporary:
    work=Path(temporary);pe=work/'input.exe';rust=work/'native.rs';native=work/'native'
    for name,code,expected in positive:
        original=image(code);pe.write_bytes(original)
        outputs=[]
        for _ in range(2):
            p=subprocess.run([str(converter),str(pe),str(rust)],capture_output=True,timeout=15)
            assert p.returncode==0,(name,p.stderr)
            outputs.append(rust.read_bytes())
        assert outputs[0]==outputs[1] and pe.read_bytes()==original
        subprocess.run(['rustc','-D','warnings',str(rust),'-o',str(native)],capture_output=True,check=True,timeout=60)
        p=subprocess.run([str(native)],capture_output=True,timeout=15)
        assert (p.returncode,p.stdout,p.stderr)==(expected,b'',b''),(name,p)
        print('LOCAL_NATIVE',name,expected)
    for name,code in negative:
        pe.write_bytes(image(code));rust.write_bytes(b'preserve')
        p=subprocess.run([str(converter),str(pe),str(rust)],capture_output=True,timeout=15)
        assert p.returncode==1 and rust.read_bytes()==b'preserve',(name,p.stderr)
    print('LOCAL_PRODUCTION_COUNTS',len(positive),'native',len(negative),'rejected')
