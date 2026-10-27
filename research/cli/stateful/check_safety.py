"""Separate mutated copies and proof certificates; frozen PEs remain untouched."""
import hashlib,json,os,struct,subprocess,sys,tempfile
from pathlib import Path
root=Path(sys.argv[1]).resolve();repo=Path(__file__).resolve().parents[3];records=[]
def run(cmd,**kw):return subprocess.run(cmd,capture_output=True,timeout=30,**kw)
with tempfile.TemporaryDirectory() as td:
 d=Path(td)
 for opt in ['O1','O2']:
  original=(root/f'tabs_{opt}.exe').read_bytes();pe=struct.unpack_from('<I',original,60)[0];raw=struct.unpack_from('<I',original,pe+24+224+20)[0]
  specs=([
   ('output-gap',0xa1,bytes.fromhex('c6443c6420'),bytes.fromhex('c6443c6520')),
   ('column-never-advances',0xa7,b'\x45',b'\x90'),
   ('eight-column-expansion-exceeds-allocation',0xa8,bytes.fromhex('83e503'),bytes.fromhex('83e507')),
   ('inclusive-input-bound',0xc9,b'\x72',b'\x76'),
   ('removed-output-store',0xa1,bytes.fromhex('c6443c6420'),b'\x90'*5),
   ('uninitialized-output-read',0x98,bytes.fromhex('8a4c1424'),bytes.fromhex('8a4c1464')),
   ('read-count-aliases-output',0x4b,b'\x10',b'\x64'),
  ] if opt=='O1' else [
   ('output-gap',0xb8,bytes.fromhex('c6443c6420'),bytes.fromhex('c6443c6520')),
   ('column-never-advances',0xbd,b'\x46',b'\x90'),
   ('eight-column-expansion-exceeds-allocation',0xbf,bytes.fromhex('83e603'),bytes.fromhex('83e607')),
   ('inclusive-input-bound',0xde,b'\x72',b'\x76'),
   ('removed-output-store',0xb8,bytes.fromhex('c6443c6420'),b'\x90'*5),
   ('uninitialized-output-read',0xb0,bytes.fromhex('8a440c24'),bytes.fromhex('8a440c64')),
   ('read-count-aliases-output',0x55,b'\x14',b'\x68'),
  ])
  for name,at,old,new in specs:
   assert original[raw+at:raw+at+len(old)]==old,(opt,name)
   changed=bytearray(original);changed[raw+at:raw+at+len(old)]=new;(d/'unsafe.exe').write_bytes(changed);(d/'out.rs').write_text('preserve')
   p=run([str(repo/'target/debug/w2l'),str(d/'unsafe.exe'),str(d/'out.rs')]);assert p.returncode==1 and (d/'out.rs').read_text()=='preserve',(opt,name,p.stderr)
   records.append(dict(config=opt,case=name,sha256=hashlib.sha256(changed).hexdigest(),diagnostic=p.stderr.decode()));(root/'safety-partial.json').write_text(json.dumps(records,indent=2)+'\n')
  proof=d/(opt+'.smt2');p=run([str(repo/'target/debug/w2l'),str(root/f'tabs_{opt}.exe'),str(d/'ok.rs')],env=dict(os.environ,W2L_STREAM_OBLIGATIONS=str(proof)));assert p.returncode==0,p.stderr
  # Strengthen BOTH use sites and incoming checks. The first edge entering the
  # expansion loop must expose 4 remaining output bytes > the false budget3.
  text=proof.read_text();assert '(reset)' not in text and '(* 4 ' in text
  wrong='\n'.join(line for line in text.replace('(* 4 ','(* 3 ').splitlines() if not line.startswith('(query'))
  wrong+=f'\n(query bad{0x109f if opt=="O1" else 0x10b6})\n'
  p=run([os.environ.get('W2L_Z3','z3'),'-in','-smt2'],input=wrong.encode());assert p.returncode==0 and p.stdout.strip()==b'sat',(opt,p.stdout,p.stderr)
  records.append(dict(config=opt,case='false-weighted-invariant',solver='sat'))
  p=run([str(repo/'target/debug/w2l'),str(root/f'tabs_{opt}.exe'),str(d/'out.rs')],env=dict(os.environ,W2L_Z3_RLIMIT='1'));assert p.returncode==1 and (d/'out.rs').read_text()=='preserve';records.append(dict(config=opt,case='solver-exhaustion',diagnostic=p.stderr.decode()))
  original=(root/f'fold_{opt}.exe').read_bytes();pe=struct.unpack_from('<I',original,60)[0];raw=struct.unpack_from('<I',original,pe+24+224+20)[0]
  # Stack arithmetic makes ESP-dependent flags unknown; CMOVA must reject.
  at=0xaa if opt=='O1' else 0xc2
  assert original[raw+at:raw+at+3]==(bytes.fromhex('80fb7a') if opt=='O1' else bytes.fromhex('80fa7a'))
  changed=bytearray(original);changed[raw+at:raw+at+3]=bytes.fromhex('83c400');(d/'unsafe.exe').write_bytes(changed)
  p=run([str(repo/'target/debug/w2l'),str(d/'unsafe.exe'),str(d/'out.rs')]);assert p.returncode==1 and (d/'out.rs').read_text()=='preserve';records.append(dict(config=opt,case='cmova-unknown-flags',diagnostic=p.stderr.decode()))
(root/'safety.json').write_text(json.dumps(records,indent=2)+'\n');print(f'{len(records)} negative checks; counts include mutated PEs, false invariant certificates and solver exhaustion')
