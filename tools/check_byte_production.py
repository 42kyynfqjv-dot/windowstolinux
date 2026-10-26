"""Literal byte-local production/native cases; expected results independent of model."""
from pathlib import Path
import struct,subprocess,tempfile
converter=Path('target/debug/w2l').resolve()
def h(s):return bytes.fromhex(s)
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


forms=[h(x) for x in ['51','c6042441','c644240142','0fb6442401','fec0','88442401','0fb64c2401','0fb60424','03c1','59','c3']]
base=b''.join(forms)
positive=[('buffer',base,132)]
for a,b,answer in [(0,255,0),(1,127,129),(0,128,129),(10,20,31)]:
 f=forms.copy();f[1]=h('c60424')+bytes([a]);f[2]=h('c6442401')+bytes([b]);positive.append(('boundary-'+str(b),b''.join(f),answer))
# POP reads modified bytes, PUSH copies them without resetting ECX.
positive.append(('reuse',base[:-1]+h('51 0fb6442401 59 c3'),67))
# INC establishes ZF while CF stays unknown; JZ consumes only ZF.
positive.append(('known-zf',h('b8ff000000 fec0 7406 b801000000 c3 b802000000 c3'),2))
# Known full EAX remains full after partial AL update, upper bytes preserved.
positive.append(('preserve-upper',h('b8ff010000 fec0 83f800 7406 b803000000 c3 b804000000 c3'),3))
# Real decoded CALL/RET contexts with suspended and shared byte allocations.
outer=h('51 c6042441 c644240142')
suffix=h('0fb60424 59 c3')
outer+=b'\xe8'+struct.pack('<i',len(suffix))+suffix
positive.append(('nested-byte',outer+base,65))
positive.append(('shared-byte',h('e806000000 e801000000 c3')+base,132))
negative=[h(x) for x in ['51 0fb60424 59 c3','51 88442401 59 c3','51 59 03c1 c3','51 83c408 c3',
 '83ec08 59 c3','51 8b442404 59 c3','51 c7042401000000 59 c3','51 56 59 c3',
 '51 51 59 c3','51 6a01 59 c3','51 b801000000 c3','fec0 c3',
 '51 33c0 7504 c6042407 0fb60424 59 c3','51 c644240107 59 51 0fb60424 59 c3']]
for prefix in ['66','67','f0','f2','f3','2e','36','3e','26','64','65']:
 for i in [0,1,2,3,4,5,6,7,9]:
  f=forms.copy();f[i]=h(prefix)+f[i];negative.append(b''.join(f))
for i,replacement in [(0,'50'),(9,'58'),(1,'c6042501'),(2,'c644240207'),(3,'0fb7442401'),(4,'fec1'),(5,'88442402'),(6,'0fb64c2402')]:
 f=forms.copy();f[i]=h(replacement);negative.append(b''.join(f))
with tempfile.TemporaryDirectory() as t:
 d=Path(t);pe=d/'p.exe';rs=d/'p.rs';exe=d/'p'
 for name,code,expected in positive:
  pe.write_bytes(image(code));outputs=[]
  for _ in range(2):
   p=subprocess.run([str(converter),str(pe),str(rs)],capture_output=True,timeout=15);assert p.returncode==0,(name,p.stderr);outputs.append(rs.read_bytes())
  assert outputs[0]==outputs[1]
  subprocess.run(['rustc','-D','warnings',str(rs),'-o',str(exe)],check=True,capture_output=True,timeout=60)
  p=subprocess.run([str(exe)],capture_output=True,timeout=15);assert (p.returncode,p.stdout,p.stderr)==(expected,b'',b''),(name,p)
  print('BYTE_NATIVE',name,expected)
 for code in negative:
  pe.write_bytes(image(code));rs.write_bytes(b'preserve');p=subprocess.run([str(converter),str(pe),str(rs)],capture_output=True,timeout=15)
  assert p.returncode==1 and rs.read_bytes()==b'preserve',(code.hex(),p.stderr)
 print('BYTE_PRODUCTION_COUNTS',len(positive),'native',len(negative),'rejected')
