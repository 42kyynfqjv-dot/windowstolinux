"""Independent authored PE/CLI/native loop regressions; no converter/model imports."""
from pathlib import Path
import struct,subprocess,tempfile
H=bytes.fromhex
CODE=H('33c0 33c9 390500204000 760f 0f1f4000 03c1 41 3b0d00204000 72f5 c3')
def image(n=5,code=CODE,sites=(6,21),base=0x400000):
    b=bytearray(2048)
    def u(at,n):struct.pack_into('<I',b,at,n)
    def w(at,n):struct.pack_into('<H',b,at,n)
    b[:2]=b'MZ';u(60,128);b[128:132]=b'PE\0\0'
    for at,nv in [(132,0x14c),(134,3),(148,224),(150,0x102),(152,0x10b),(220,3),(222,0x8540)]:w(at,nv)
    for at,nv in [(168,4096),(180,base),(184,4096),(188,512),(208,16384),(212,512),(224,0x100000),(228,4096),(232,0x100000),(236,4096),(244,16)]:u(at,nv)
    code=bytearray(code)
    if base!=0x400000:
        for at in (6,21):struct.pack_into('<I',code,at,base+8192)
    reloc=struct.pack('<II',4096,8+2*((len(sites)+1)//2*2))+b''.join(struct.pack('<H',0x3000+s) for s in sites)
    if len(sites)%2:reloc+=b'\0\0'
    for i,(rva,raw,data,flags) in enumerate([(4096,512,code,0x60000020),(8192,1024,struct.pack('<II',n,n),0xc0000040),(12288,1536,reloc,0x42000040)]):
        for offset,nv in [(8,len(data)),(12,rva),(16,512),(20,raw),(36,flags)]:u(376+40*i+offset,nv)
        b[raw:raw+len(data)]=data
    u(288,12288);u(292,len(reloc));return b

def put(b,at,n):b=bytearray(b);struct.pack_into('<I',b,at,n);return b
positive=[(str(n),image(n),answer) for n,answer in [(0,0),(1,0),(2,1),(5,10),(6,15),(23,253)]]
positive.append(('other-preferred-base',image(base=0x10000000),10))
negative=[]
for n in (24,254):negative.append(('wide-exit',image(n),'portable exit domain'))
for n in (255,256,0x7fffffff,0x80000000,0xffffffff):negative.append(('budget',image(n),'iteration budget'))
for at in set(range(28))-set(range(6,10))-set(range(21,25)):
    code=bytearray(CODE);code[at]^=1
    negative.append(('graph-byte',image(code=code),None))
for at,v in [(26,254),(26,246),(26,229),(25,0x73),(25,0x7c),(18,0x49),(18,0x90),(1,0xc1),(3,0xc8),(19,0x89)]:
    code=bytearray(CODE);code[at]=v;negative.append(('unproved-cycle-or-state',image(code=code),'unproved graph'))
for length in range(1,28):negative.append(('truncate',image(code=CODE[:length]),None))
for prefix in ('66','67','f0','f2','f3','2e','36','3e','26','64','65'):negative.append(('prefix',image(code=H(prefix)+CODE),None))
negative.append(('extra-ret',image(code=CODE+b'\xc3'),'complete graph'))
for sites in [(6,),(6,21,6),(6,7),(7,21),(6,21,0)]:negative.append(('reloc',image(sites=sites),None))
for va in (0x3fffff,0x400000,0x401000,0x401fff,0x402005,0x402008,0x403000,0xffffffff):
    b=put(put(image(),518,va),533,va);negative.append(('full-target',b,None))
negative.append(('equal-value-different-word',put(image(),533,0x402004),'same word'))
for at,n in [(424,513),(436,512),(168,4097),(428,4096)]:negative.append(('mapping',put(image(),at,n),None))
b=put(put(image(),320,8192),324,4);negative.append(('tls',b,'metadata closure'))
b=image();b[1548:1560]=struct.pack('<IIHH',8192,12,0x3004,0);b=put(put(b,292,24),464,24)
negative.append(('loader-write-unused-data',b,'site must be code'))
converter=Path('target/debug/w2l').resolve()
with tempfile.TemporaryDirectory() as d:
    p=Path(d);pe=p/'in.exe';rs=p/'native.rs';elf=p/'native'
    for name,blob,expected in positive:
        pe.write_bytes(blob);sources=[]
        for _ in range(2):
            r=subprocess.run([converter,pe,rs],capture_output=True,timeout=15);assert r.returncode==0,(name,r.stderr);sources.append(rs.read_bytes())
        assert sources[0]==sources[1] and pe.read_bytes()==blob
        assert b'loop {' in sources[0] and b'run_bound(' in sources[0]
        subprocess.run(['rustc','-D','warnings',rs,'-o',elf],capture_output=True,check=True,timeout=60)
        r=subprocess.run([elf],capture_output=True,timeout=15);assert (r.returncode,r.stdout,r.stderr)==(expected,b'',b''),(name,r)
    for name,blob,reason in negative:
        pe.write_bytes(blob);rs.write_bytes(b'preserve')
        r=subprocess.run([converter,pe,rs],capture_output=True,timeout=15)
        assert r.returncode==1 and rs.read_bytes()==b'preserve',(name,r.stderr)
        assert reason is None or reason in r.stderr.decode(),(name,reason,r.stderr)
print('FINITE_LOOP_PRODUCTION',len(positive),'native',len(negative),'rejected')
