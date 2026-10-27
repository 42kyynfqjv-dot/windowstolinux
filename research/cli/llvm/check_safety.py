"""Adversarial copies of frozen LLVM programs; originals and baselines stay intact."""
import hashlib,json,os,struct,subprocess,sys,tempfile
from pathlib import Path
root=Path(sys.argv[1]).resolve();repo=Path(__file__).resolve().parents[3];records=[]
def run(cmd,**kw):return subprocess.run(cmd,capture_output=True,timeout=30,**kw)
with tempfile.TemporaryDirectory() as td:
 d=Path(td)
 for family in ['fold','escape','tabs']:
  for opt in ['O1','O2']:
   stem=family+'_'+opt;original=(root/(stem+'.exe')).read_bytes();pe=struct.unpack_from('<I',original,60)[0];raw=struct.unpack_from('<I',original,pe+24+224+20)[0]
   if family!='tabs':
    # EOF path writes only CL; consuming all 32 bits of the spill must fail.
    at={('fold','O1'):0x137,('fold','O2'):0x60,('escape','O1'):0x111,('escape','O2'):0x60}[family,opt]
    specs=[('unknown-upper-scalar-spill',at,bytes.fromhex('807c240800'),bytes.fromhex('837c240800'))]
    at={('fold','O1'):0x7d,('fold','O2'):0xbe,('escape','O1'):0x7d,('escape','O2'):0xac}[family,opt]
    old=(bytes.fromhex('8a540c14') if family=='escape' and opt=='O1' else bytes.fromhex('0fb65c0c14') if family=='fold' else bytes.fromhex('0fb6540c14'))
    specs.append(('uninitialized-output-load',at,old,old[:-1]+b'\x54'))
    specs.append(('past-fresh-read-prefix',at,old,old[:-1]+b'\x15'))
   else:
    at=0x8b if opt=='O1' else 0xe0
    specs=[('output-gap',at,bytes.fromhex('c644345020'),bytes.fromhex('c644345120')),
           ('missing-output-store',at,bytes.fromhex('c644345020'),b'\x90'*5)]
    at=0x82 if opt=='O1' else 0xc7
    old=bytes.fromhex('8a540c10' if opt=='O1' else '0fb6540c10')
    specs.append(('past-fresh-read-prefix',at,old,old[:-1]+b'\x11'))
   for name,at,old,new in specs:
    assert original[raw+at:raw+at+len(old)]==old,(stem,name)
    changed=bytearray(original);changed[raw+at:raw+at+len(old)]=new
    (d/'unsafe.exe').write_bytes(changed);(d/'out.rs').write_text('preserve')
    p=run([str(repo/'target/debug/w2l'),str(d/'unsafe.exe'),str(d/'out.rs')]);assert p.returncode==1 and (d/'out.rs').read_text()=='preserve',(stem,name,p.stderr)
    records.append(dict(program=stem,case=name,sha256=hashlib.sha256(changed).hexdigest(),diagnostic=p.stderr.decode()));(root/'safety-partial.json').write_text(json.dumps(records,indent=2)+'\n')
   if family=='tabs':
    proof=d/(stem+'.smt2');p=run([str(repo/'target/debug/w2l'),str(root/(stem+'.exe')),str(d/'ok.rs')],env=dict(os.environ,W2L_STREAM_OBLIGATIONS=str(proof)));assert p.returncode==0,p.stderr
    text=proof.read_text();assert '(* 4 ' in text
    wrong='\n'.join(line for line in text.replace('(* 4 ','(* 3 ').splitlines() if not line.startswith('(query'))
    wrong+=f'\n(query bad{0x1089 if opt=="O1" else 0x10d1})\n'
    p=run([os.environ.get('W2L_Z3','z3'),'-in','-smt2'],input=wrong.encode());assert p.returncode==0 and p.stdout.strip()==b'sat',(stem,p.stdout,p.stderr)
    records.append(dict(program=stem,case='false-modular-expansion-invariant',solver='sat'))
    (d/'out.rs').write_text('preserve');p=run([str(repo/'target/debug/w2l'),str(root/(stem+'.exe')),str(d/'out.rs')],env=dict(os.environ,W2L_Z3_RLIMIT='1'));assert p.returncode==1 and (d/'out.rs').read_text()=='preserve'
    records.append(dict(program=stem,case='solver-exhaustion',diagnostic=p.stderr.decode()))
   assert hashlib.sha256((root/(stem+'.exe')).read_bytes()).hexdigest()==hashlib.sha256(original).hexdigest()
(root/'safety.json').write_text(json.dumps(records,indent=2)+'\n');print(f'{len(records)} negative checks: 18 mutated PEs, two false invariants, two solver exhaustion checks')
