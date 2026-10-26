"""Independent literal PE/CLI/native cases; no production/model/generator imports."""
from pathlib import Path
import struct,subprocess,tempfile
H=bytes.fromhex
CODE=H('8b0d04304000 a108304000 03c8 a100304000 03c1 c3')
DATA=H('02000000 03000000 04000000')
def image(code=CODE,data=DATA,sites=(2,7,14)):
    b=bytearray(2048)
    def u(at,n):struct.pack_into('<I',b,at,n)
    def w(at,n):struct.pack_into('<H',b,at,n)
    b[:2]=b'MZ';u(60,128);b[128:132]=b'PE\0\0'
    for at,n in [(132,0x14c),(134,3),(148,224),(150,0x102),(152,0x10b),(220,3),(222,0x8540)]:w(at,n)
    for at,n in [(168,4096),(180,0x400000),(184,4096),(188,512),(208,16384),(212,512),(224,0x100000),(228,4096),(232,0x100000),(236,4096),(244,16)]:u(at,n)
    # Data RVA3000 matches literal code; immutable padding section is unnecessary,
    # so place code at1000, data2000 and patch operands to2000 for this authored PE.
    code=bytearray(code)
    for pos in (2,7,14):
        if len(code)>=pos+4 and code[pos:pos+4] in (H('04304000'),H('08304000'),H('00304000')):code[pos+1]=0x20
    reloc=struct.pack('<II',4096,8+2*((len(sites)+1)//2*2))+b''.join(struct.pack('<H',0x3000+x) for x in sites)
    if len(sites)%2:reloc+=b'\0\0'
    for i,(rva,raw,content,flags) in enumerate([(4096,512,code,0x60000020),(8192,1024,data,0xc0000040),(12288,1536,reloc,0x42000040)]):
        at=376+40*i
        for offset,n in [(8,len(content)),(12,rva),(16,512),(20,raw),(36,flags)]:u(at+offset,n)
        b[raw:raw+len(content)]=content
    u(288,12288);u(292,len(reloc))
    return b

def put(b,at,n):b=bytearray(b);struct.pack_into('<I',b,at,n);return b
positive=[('array',image(),9),('wrap',image(data=H('00000000 ffffffff 01000000')),0),('signed',image(data=H('00000080 ffffff7f 01000000')),0),('max',image(data=H('00000000 ff000000 00000000')),255),('other-image',image(data=H('01000000 02000000 03000000')),6)]
positive += [('one-read',image(code=H('a100204000c3'),sites=(1,)),2),('unaligned',image(code=H('a101204000c3'),data=H('00010000 00000000 00000000'),sites=(1,)),1)]
negative=[('unknown-ecx',image(code=H('a100204000 a104204000 03c1 c3'),sites=(1,6)),'unknown ECX')]
for va in (0x3fffff,0x400000,0x401000,0x401fff,0x402009,0x40200c,0x403000,0xffffffff):negative.append(('target',put(image(),514,va),None))
for sites in [(2,7),(2,7,14,2),(2,3,7,14),(0,7,14),(2,7,13),(2,7,18)]:negative.append(('binding',image(sites=sites),None))
b=image(code=CODE[:-1]+H('03c103c1c3'),sites=(2,7,14,20))
reloc=bytes(b[1536:2048]);b=b[:1024]+bytearray(0xb000)+reloc
for at,n in [(180,0xc1030000),(208,0xe000),(424,0xb000),(432,0xb000),(288,0xd000),(468,0xd000),(476,0xb400),(514,0xc1032004),(519,0xc1032008),(526,0xc1032000)]:b=put(b,at,n)
b[1024:1036]=DATA
negative.append(('unbound',b,'unbound loader write'))
b=image(data=DATA+b'\0'*4)
# A second sorted relocation page writes the unused fourth data word.
b[1552:1564]=struct.pack('<IIHH',8192,12,0x300c,0);b=put(b,292,28);b=put(b,464,28)
negative.append(('unused-data-loader-write',b,'site must be code'))
for op in ('e800000000','eb00','72fe','a300204000','890d00204000','8b00','ffd0','cd80'):
    negative.append(('effect',image(code=CODE[:-1]+H(op)+b'\xc3'),'unsupported effect'))
for prefix in ('66','67','f0','f2','f3','2e','36','3e','26','64','65'):
    negative.append(('prefix',image(code=H(prefix)+CODE),None))
for length in range(1,len(CODE)):negative.append(('truncate',image(code=CODE[:length]),None))
negative += [('tail',image(code=CODE+b'\xcc'),'code after return'),('exit256',image(data=H('00000000 00010000 00000000')),'exit domain'),('virtualtail',put(image(),424,513),None),('rawalias',put(image(),436,512),None),('entry',put(image(),168,4097),None)]
# An extra complete optional-directory range must prevent executable eligibility.
b=put(put(image(),320,8192),324,4);negative.append(('tls',b,'metadata closure'))
# Complete valid mapping with >1024 otherwise admitted instructions. Preserve
# literal operand RVAs while moving raw data/relocation backing after larger code.
code=CODE[:-1]+H('03c1')*1020+b'\xc3'
b=image();data=bytes(b[1024:1536]);reloc=bytes(b[1536:2048])
b=b[:512]+bytearray(2560)+data+reloc
b[512:512+len(code)]=code
# This authored code uses data RVA2000 rather than frozen RVA3000.
for pos in (2,7,14):b[512+pos+1]=0x20
for at,n in [(384,len(code)),(392,2560),(436,3072),(476,3584)]:b=put(b,at,n)
negative.append(('instruction-cap',b,'instruction cap'))
converter=Path('target/debug/w2l').resolve()
with tempfile.TemporaryDirectory() as d:
    p=Path(d);pe=p/'in.exe';rs=p/'native.rs';elf=p/'native'
    for name,b,exitcode in positive:
        pe.write_bytes(b);sources=[]
        for _ in range(2):
            r=subprocess.run([converter,pe,rs],capture_output=True);assert r.returncode==0,(name,r.stderr);sources.append(rs.read_bytes())
        assert sources[0]==sources[1] and pe.read_bytes()==b
        subprocess.run(['rustc','-D','warnings',rs,'-o',elf],check=True,capture_output=True)
        r=subprocess.run([elf],capture_output=True);assert (r.returncode,r.stdout,r.stderr)==(exitcode,b'',b'')
    for name,b,reason in negative:
        pe.write_bytes(b);rs.write_bytes(b'preserve');r=subprocess.run([converter,pe,rs],capture_output=True)
        assert r.returncode==1 and rs.read_bytes()==b'preserve',(name,r.stderr)
        assert reason is None or reason in r.stderr.decode(),(name,reason,r.stderr)
print('IMAGE_READ_PRODUCTION',len(positive),'native',len(negative),'rejected')
