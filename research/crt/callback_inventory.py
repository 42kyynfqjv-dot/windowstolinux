"""Exact authored held_crt profile evidence, not a general PE parser or effect proof."""
import hashlib,json,re,struct,sys
from pathlib import Path
root=Path(sys.argv[1]);b=(root/'held_crt.exe').read_bytes()
r=next(x for x in json.loads((root/'heldout-x86.json').read_text()) if x['kind']=='held_crt')
assert hashlib.sha256(b).hexdigest()==r['sha256'] and not r['conversion_accepted']
u=lambda p:struct.unpack_from('<I',b,p)[0]
p=u(60);o=p+24;table=o+struct.unpack_from('<H',b,p+20)[0];base=u(o+28)
secs=[struct.unpack_from('<IIII',b,table+i*40+8) for i in range(struct.unpack_from('<H',b,p+6)[0])]
def raw(v,n=4):
 a=[pos+v-start for vs,start,size,pos in secs if start<=v and v+n<=start+min(vs,size)]
 assert len(a)==1 and a[0]+n<=len(b);return a[0]
def word(v):return u(raw(v))
def name(v):
 out=bytearray()
 for i in range(256):
  c=b[raw(v+i,1)]
  if not c:return out.decode('ascii')
  out.append(c)
 raise ValueError('long import name')
imports={};at=raw(u(o+104),20)
for _ in range(32):
 orig,stamp,chain,dll,iat=struct.unpack_from('<IIIII',b,at);at+=20
 if not any((orig,stamp,chain,dll,iat)):break
 for i in range(256):
  val=word(orig+4*i)
  if not val:break
  assert val<0x80000000
  imports[base+iat+4*i]=name(dll)+'!'+name(val+2)
 else:raise ValueError('thunk cap')
else:raise ValueError('descriptor cap')
tables={hex(start):[word(v) for v in range(start,end,4)] for start,end in [(0x20b8,0x20c0),(0x20c4,0x20d0)]}
assert tables=={'0x20b8':[0,base+0x10f0],'0x20c4':[0,base+0x1030,base+0x10e0]}
relocs=set();rv=u(o+136);size=u(o+140);pos=raw(rv,size);end=pos+size
while pos<end:
 page,sz=struct.unpack_from('<II',b,pos);assert sz>=8 and pos+sz<=end
 for i in range(pos+8,pos+sz,2):
  v=struct.unpack_from('<H',b,i)[0]
  if v>>12==3:relocs.add(page+(v&4095))
 pos+=sz
assert {0x20bc,0x20c8,0x20cc}<=relocs
calls=[]
for line in (root/'held_crt-disassembly.txt').read_text().splitlines():
 m=re.match(r'\s*([0-9A-F]{8}):.*\bcall\s+([0-9A-F]{8})\s*$',line)
 if not m:continue
 site,target=(int(v,16) for v in m.groups());rv=site-base
 if not 0x1030<=rv<0x1102:continue
 a=raw(rv,5);assert b[a]==0xe8 and site+5+struct.unpack_from('<i',b,a+1)[0]==target
 t=raw(target-base,6);imported=None
 if b[t:t+2]==b'\xff\x25':imported=imports.get(u(t+2))
 calls.append(dict(site_rva=rv,target_rva=target-base,imported=imported))
out=dict(pe_sha256=r['sha256'],tables=tables,relocated_table_sites=[0x20bc,0x20c8,0x20cc],direct_calls=calls,
 initial_tls_slots=[word(0x30f0),word(0x30f4)],complete_effect_proof=False,emission_allowed=False)
path=root/'crt-callbacks.json'
if len(sys.argv)>2:assert json.loads(path.read_text())==out
else:path.write_text(json.dumps(out,indent=2)+'\n')
print('CRT_CALLBACKS',json.dumps(out))
