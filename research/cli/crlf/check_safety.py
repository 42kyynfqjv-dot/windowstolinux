"""Production rejection tests on separate byte copies; originals stay unchanged."""
import hashlib,json,os,struct,subprocess,sys,tempfile
from pathlib import Path
root=Path(sys.argv[1]).resolve();repo=Path(__file__).resolve().parents[3];records=[]
def run(cmd,**kw):return subprocess.run(cmd,capture_output=True,timeout=30,**kw)
with tempfile.TemporaryDirectory() as td:
 d=Path(td)
 for opt in ['O1','O2']:
  original=(root/f'filter_{opt}.exe').read_bytes();pe=struct.unpack_from('<I',original,60)[0];raw=struct.unpack_from('<I',original,pe+24+224+20)[0]
  specs=([
   ('output-gap',0xb5,b'\x88\x54\x3c\x24',b'\x88\x54\x3c\x25'),
   ('uninitialized-before-input',0xa3,b'\xa8\0\0\0',b'\xa7\0\0\0'),
   ('inclusive-input-bound',0xd2,b'\x72',b'\x76'),
   ('removed-output-initializer',0xbb,b'\xc6\x44\x3c\x24\x0d',b'\x90'*5),
   ('conditional-unknown-source',0x93,b'\xf7',b'\xf2'),
   ('count-overlaps-output',0x4b,b'\x10',b'\x24'),
   ('wrong-saved-register',0x14c,b'\x5f',b'\x5e'),
  ] if opt=='O1' else [
   ('output-gap',0xc5,b'\x88\x4c\x3c\x24',b'\x88\x4c\x3c\x25'),
   ('uninitialized-before-input',0xb3,b'\xa8\0\0\0',b'\xa7\0\0\0'),
   ('inclusive-input-bound',0xe4,b'\x72',b'\x76'),
   ('removed-output-initializer',0xcb,b'\xc6\x44\x3c\x24\x0d',b'\x90'*5),
   ('unknown-count-on-eof',0x79,b'\x33\xd2',b'\x33\xc0'),
   ('count-overlaps-output',0x4b,b'\x10',b'\x24'),
   ('wrong-saved-register',0x145,b'\x5f',b'\x5e'),
  ])
  for name,at,old,new in specs:
   assert original[raw+at:raw+at+len(old)]==old,(opt,name)
   changed=bytearray(original);changed[raw+at:raw+at+len(old)]=new;(d/'unsafe.exe').write_bytes(changed);(d/'out.rs').write_text('preserve')
   p=run([str(repo/'target/debug/w2l'),str(d/'unsafe.exe'),str(d/'out.rs')])
   assert p.returncode==1 and (d/'out.rs').read_text()=='preserve',(opt,name,p.stderr)
   records.append(dict(config=opt,case=name,sha256=hashlib.sha256(changed).hexdigest(),diagnostic=p.stderr.decode()))
  (d/'original.exe').write_bytes(original)
  for name,env in [('solver-exhaustion',dict(os.environ,W2L_Z3_RLIMIT='1')),('missing-solver',dict(os.environ,W2L_Z3=str(d/'missing')))]:
   (d/'out.rs').write_text('preserve');p=run([str(repo/'target/debug/w2l'),str(d/'original.exe'),str(d/'out.rs')],env=env)
   assert p.returncode==1 and (d/'out.rs').read_text()=='preserve'
   records.append(dict(config=opt,case=name,diagnostic=p.stderr.decode()))
  # Mutate only the emitted proof certificate, never the original PE. A false
  # candidate must fail its independent first phase even if later assumptions
  # make a safety query easy. No candidate is an admission oracle by itself.
  proof=d/(opt+'.smt2');p=run([str(repo/'target/debug/w2l'),str(d/'original.exe'),str(d/'ok.rs')],env=dict(os.environ,W2L_STREAM_OBLIGATIONS=str(proof)))
  assert p.returncode==0,p.stderr
  first=proof.read_text().split('(reset)')[0];lines=first.splitlines();query=next(x for x in lines if x.startswith('(rule') and x.endswith('hint0))'))
  # Required output+pending <= input (instead of input+1) is false for carried CR.
  import re
  wrong,n=re.subn(r'(\(not \(<= \(\+ r\d r\d\) \(\+ r\d) 1\)',r'\1 0)',query);assert n==1
  first=first.replace(query,wrong);p=run([os.environ.get('W2L_Z3','z3'),'-in','-smt2'],input=first.encode())
  assert p.returncode==0 and p.stdout.strip()==b'sat',(opt,p.stdout,p.stderr)
  records.append(dict(config=opt,case='false-independent-capacity-hint',solver='sat'))
(root/'safety.json').write_text(json.dumps(records,indent=2)+'\n')
print('14 unsafe PE mutations + 4 unavailable/exhausted solver checks + 2 false-hint proofs rejected')
