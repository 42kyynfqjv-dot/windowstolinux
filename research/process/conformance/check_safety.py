"""Mutate disposable copies only; each unsupported access must fail production proof."""
import hashlib,json,os,struct,subprocess,sys,tempfile
from pathlib import Path
root=Path(sys.argv[1]);repo=Path(__file__).resolve().parents[3];rows=[]
def run(cmd,**kw):return subprocess.run(cmd,capture_output=True,timeout=40,**kw)
with tempfile.TemporaryDirectory() as tmp:
 d=Path(tmp);original=(root/'slice_O2.exe').read_bytes();pe=struct.unpack_from('<I',original,60)[0];table=pe+24+224;raw=struct.unpack_from('<I',original,table+20)[0];size=struct.unpack_from('<I',original,table+8)[0];code=original[raw:raw+size]
 for name,old,new in [
  ('uninitialized-preceding-padding','ba01000000','ba00000000'),
  ('biased-store-before-input','88441417','88441416'),
  ('fresh-read-one-past','8a441418','8a441419'),
  ('output-length-past-read','83e901','83c101'),
  ('protected-count-cell','88441417','8844140b')]:
  old=bytes.fromhex(old);new=bytes.fromhex(new);assert code.count(old)==1,(name,code.count(old));at=raw+code.index(old)
  bad=bytearray(original);bad[at:at+len(old)]=new;(d/'unsafe.exe').write_bytes(bad);(d/'out.rs').write_text('preserve')
  p=run([str(repo/'target/debug/w2l'),str(d/'unsafe.exe'),str(d/'out.rs')]);assert p.returncode==1 and (d/'out.rs').read_text()=='preserve',(name,p.stderr)
  rows.append(dict(case=name,mutated_sha256=hashlib.sha256(bad).hexdigest(),diagnostic=p.stderr.decode()))
 for name in ['slice','swap']:
  (d/'out.rs').write_text('preserve');p=run([str(repo/'target/debug/w2l'),str(root/(name+'_O2.exe')),str(d/'out.rs')],env=dict(os.environ,W2L_Z3_RLIMIT='1'))
  assert p.returncode==1 and (d/'out.rs').read_text()=='preserve';rows.append(dict(case=name+'-solver-budget',diagnostic=p.stderr.decode()))
 assert (root/'slice_O2.exe').read_bytes()==original
(root/'safety.json').write_text(json.dumps(rows,indent=2)+'\n');print('Five independent unsafe mutations and two solver-budget rejections retained')
