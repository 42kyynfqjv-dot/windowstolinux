"""Frozen original v1 semantics, including pipe EOF error11, never silently corrected."""
import hashlib,json,subprocess,sys,tempfile
from pathlib import Path
here=Path(__file__).resolve().parent;repo=here.parents[1];root=Path(sys.argv[1]);r=json.loads((root/'report.json').read_text());m=json.loads((here/'frozen.json').read_text());cases=json.loads((here/'cases.json').read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(cmd,**kw):return subprocess.run(cmd,timeout=40,stderr=subprocess.PIPE,stdout=kw.pop('stdout',subprocess.PIPE),**kw)
assert r['manifest']==m and len(r['programs'])==2
for name,h in m['sha256'].items():assert sha(here/name)==h
rows=[]
with tempfile.TemporaryDirectory() as tmp:
 d=Path(tmp)
 for row in r['programs']:
  stem='uppercase_'+row['config'];pe=root/(stem+'.exe');assert sha(pe)==row['pe_sha256'];assert row['source_sha256']==m['sha256']['filter.c']
  target=d/(stem+'.rs');target.write_text('preserve');p=run([str(repo/'target/debug/w2l'),str(pe),str(target)])
  got=dict(config=row['config'],pe_sha256=sha(pe),accepted=p.returncode==0);rows.append(got)
  assert got['accepted']==row['conversion']['accepted']
  if p.returncode:
   assert p.returncode==1 and target.read_text()=='preserve' and p.stderr.decode()==row['conversion']['error'];continue
  assert sha(target)==row['conversion']['rust_sha256'] and target.read_bytes()==(root/(stem+'.rs')).read_bytes();got['rust_sha256']=sha(target)
  exe=d/stem;p=run(['rustc','--edition=2021',str(target),'-o',str(exe)]);assert p.returncode==0,p.stderr
  got['observations']=[];assert len(row['observations'])==len(cases)
  for case,expected in zip(cases,row['observations']):
   assert expected=={k:case[k] for k in expected};path=d/'input.bin';path.write_bytes(bytes.fromhex(case['input_hex']))
   with path.open('rb') as f:p=run([str(exe)],stdin=f)
   obs=dict(name=case['name'],exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex());assert obs==expected;got['observations'].append(obs)
  p=run([str(exe)],input=b'aZ\x00\xff');obs=dict(exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex());assert obs==row['pipe_eof']==dict(exit=11,stdout_hex='415a00ff',stderr_hex='');got['pipe_eof']=obs
  with path.open('wb') as f:p=run([str(exe)],stdin=f)
  assert dict(exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex())==row['read_failure']
  path.write_bytes(b'a')
  with path.open('rb') as f,path.open('rb') as dest:p=run([str(exe)],stdin=f,stdout=dest)
  assert dict(exit=p.returncode,destination_after_hex=path.read_bytes().hex(),stderr_hex=p.stderr.hex())==row['write_failure'];got['real_failure_comparisons']=2
(root/'native.json').write_text(json.dumps(rows,indent=2)+'\n');print(json.dumps([dict(config=x['config'],accepted=x['accepted'],comparisons=len(x.get('observations',[]))+(3 if x['accepted'] else 0)) for x in rows],indent=2))
