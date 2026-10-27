"""Independent unsafe byte edits and emitted-code effects, never baseline repairs."""
import hashlib,json,os,struct,subprocess,sys,tempfile
from pathlib import Path
root=Path(sys.argv[1]).resolve();repo=Path(__file__).resolve().parents[3]
exe=repo/'target/debug/w2l';rows=[]
def u(b,p):return struct.unpack_from('<I',b,p)[0]
def convert(pe,out,env=None):return subprocess.run([str(exe),str(pe),str(out)],env=env,capture_output=True,timeout=30)
with tempfile.TemporaryDirectory() as tmp:
 d=Path(tmp)
 for opt in ['O1','O2']:
  original=(root/f'uppercase_v2_{opt}.exe').read_bytes();pe=u(original,60);table=pe+24+224;raw=u(original,table+20)
  # Offsets below describe fixed decoded instructions in the preregistered
  # artifacts, not acceptance logic. Assert old bytes before each mutation.
  specs=([
   ('inclusive-index-bound',0x6f,b'\x72',b'\x76'),
   ('protected-save-owner',0x33,b'\x5f',b'\x5e'),
   ('oversized-read-region',0xb2,b'\x00\x01\x00\x00',b'\x01\x01\x00\x00'),
   ('wrong-count-load',0x3a,b'\xfc',b'\xf8'),
  ] if opt=='O1' else [
   ('inclusive-index-bound',0xa5,b'\x72',b'\x76'),
   ('protected-save-owner',0x10d,b'\x5b',b'\x5e'),
   ('oversized-read-region',0x46,b'\x00\x01\x00\x00',b'\x01\x01\x00\x00'),
   ('stale-count-after-fresh-read',0xe7,b'\x14',b'\x18'),
  ])
  branch=0xc8 if opt=='O1' else 0xfc
  old=original[raw+branch:raw+branch+6];assert old[:2]==b'\x0f\x85'
  specs.append(('coincident-successor-must-retain-both-outcomes',branch,old,b'\x0f\x84\0\0\0\0'))
  for name,offset,old,new in specs:
   assert original[raw+offset:raw+offset+len(old)]==old,(opt,name)
   changed=bytearray(original);changed[raw+offset:raw+offset+len(old)]=new
   pefile=d/'unsafe.exe';out=d/'unsafe.rs';pefile.write_bytes(changed);out.write_text('preserve')
   p=convert(pefile,out);assert p.returncode==1 and out.read_text()=='preserve',(opt,name,p.stderr)
   if name=='inclusive-index-bound' or (opt=='O2' and name=='coincident-successor-must-retain-both-outcomes'):assert '"sat"' in p.stderr.decode(),p.stderr
   rows.append(dict(config=opt,case=name,error=p.stderr.decode(),sha256=hashlib.sha256(changed).hexdigest()))
  pefile=d/'original.exe';pefile.write_bytes(original)
  for name,env in [('solver-exhaustion',dict(os.environ,W2L_Z3_RLIMIT='1')),('solver-unavailable',dict(os.environ,W2L_Z3=str(d/'missing-solver')))]:
   out=d/'out.rs';out.write_text('preserve');p=convert(pefile,out,env)
   assert p.returncode==1 and out.read_text()=='preserve',(name,p.stderr)
   rows.append(dict(config=opt,case=name,error=p.stderr.decode()))
  # Semantic variation: change SUB byte,32 to SUB byte,31. This is a
  # separately labelled mutated fixture, NOT an unchanged compiler baseline.
  off=0x64 if opt=='O1' else 0x9d;assert original[raw+off]==32
  changed=bytearray(original);changed[raw+off]=31;pefile=d/'semantic.exe';pefile.write_bytes(changed);out=d/'semantic.rs'
  p=convert(pefile,out);assert p.returncode==0,p.stderr
  p=subprocess.run(['rustc','--edition=2021',str(out),'-o',str(d/'semantic')],capture_output=True,timeout=30);assert p.returncode==0,p.stderr
  payload=bytes(range(256))*5;expected=bytes(v-31 if 97<=v<=122 else v for v in payload)
  p=subprocess.run([str(d/'semantic')],input=payload,capture_output=True,timeout=30)
  assert (p.returncode,p.stdout,p.stderr)==(0,expected,b'')
  rows.append(dict(config=opt,case='decoded-subtraction-immediate-changes-output',native_only=True,exit=p.returncode))
 (root/'safety-native.json').write_text(json.dumps(rows,indent=2)+'\n')
print('10 unsafe graph/frame/epoch mutations +4 unavailable/exhausted solver rejections;2 independent emitted arithmetic variations')
