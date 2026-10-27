"""Production stream intake/binding rejection gate; no emission acceptance."""
import json,struct,subprocess,sys,tempfile
from pathlib import Path
root=Path(sys.argv[1]);repo=Path(__file__).resolve().parents[3]
exe=repo/'target/debug'/('w2l.exe' if sys.platform=='win32' else 'w2l')
def u(b,a):return struct.unpack_from('<I',b,a)[0]
def put(b,a,n):struct.pack_into('<I',b,a,n)
report=json.loads((root/'report.json').read_text());results=[]
with tempfile.TemporaryDirectory() as temp:
 d=Path(temp)
 for row in report['programs']:
  b=(root/('uppercase_v2_'+row['config']+'.exe')).read_bytes();p=u(b,60);o=p+24;t=o+224
  sections=[tuple(u(b,t+i*40+k) for k in [12,16,20]) for i in range(3)]
  def file(rva):
   for v,n,r in sections:
    if v<=rva<v+n:return r+rva-v
   raise AssertionError('RVA')
  descriptor=file(u(b,o+104));ilt=file(u(b,descriptor));iat=file(u(b,descriptor+16));dll=file(u(b,descriptor+12))
  cases=[]
  def mutation(name,f):
   c=bytearray(b);f(c);cases.append((name,c))
  mutation('duplicate-function',lambda c:(put(c,ilt+4,u(c,ilt)),put(c,iat+4,u(c,iat))))
  mutation('ordinal',lambda c:(put(c,ilt,0x80000001),put(c,iat,0x80000001)))
  mutation('terminator',lambda c:(put(c,ilt+16,1),put(c,iat+16,1)))
  mutation('table-alias',lambda c:put(c,descriptor, u(c,descriptor+16)))
  mutation('dll-identity',lambda c:c.__setitem__(dll,ord('X')))
  mutation('name-identity',lambda c:c.__setitem__(file(u(c,ilt))+2,ord('X')))
  for name,data in [('original',b)]+cases:
   pe=d/'test.exe';target=d/'out.rs';pe.write_bytes(data);target.write_text('preserve')
   r=subprocess.run([str(exe),str(pe),str(target)],capture_output=True,timeout=30)
   if name=='original':assert r.returncode==0 and target.read_text()!='preserve',r.stderr
   else:assert r.returncode==1 and target.read_text()=='preserve',(name,r.stderr)
   results.append(dict(config=row['config'],case=name,error=r.stderr.decode()))
(root/'binding-rejections.json').write_text(json.dumps(results,indent=2)+'\n')
print('Production binding:2 originals prove and emit;12 malformed imports rejected')
