"""Same hashed PE and emitted Rust, accepted executions or exact rejection evidence."""
import hashlib,json,os,subprocess,sys,tempfile
from pathlib import Path
root=Path(sys.argv[1]).resolve();repo=Path(__file__).resolve().parents[3];report=json.loads((root/'report.json').read_text());cases=json.loads((Path(__file__).parent/'cases.json').read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(cmd,**kw):return subprocess.run(cmd,timeout=30,**(dict(stderr=subprocess.PIPE) if 'stdout' in kw else dict(capture_output=True)),**kw)
rows=[]
with tempfile.TemporaryDirectory() as td:
 d=Path(td)
 for row in report['programs']:
  stem=row['name']+'_'+row['config'];pe=root/(stem+'.exe');target=d/(stem+'.rs');target.write_text('preserve');assert sha(pe)==row['pe_sha256']
  p=run([str(repo/'target/debug/w2l'),str(pe),str(target)]);c=row['conversion'];assert p.returncode==c['exit']
  got=dict(name=row['name'],config=row['config'],pe_sha256=sha(pe),conversion_exit=p.returncode,stderr=p.stderr.decode(errors='replace'))
  if p.returncode:
   assert p.returncode==1 and target.read_text()=='preserve'
   got['windows_stderr']=c['stderr'];got['diagnostic_text_equal']=got['stderr']==c['stderr']
   def budget(text):return 'wall-time budget exhausted' in text or ('max. resource limit exceeded' in text and '"sat"' not in text)
   if budget(got['stderr']) and budget(c['stderr']):got['rejection_class']='proof-budget';got['exact_diagnostic_parity']=False
   else:assert got['stderr']==c['stderr'],(stem,got['stderr'],c['stderr']);got['rejection_class']='exact-diagnostic'
   rows.append(got);(root/'native-partial.json').write_text(json.dumps(rows,indent=2)+'\n');continue
  assert sha(target)==c['rust_sha256'] and target.read_bytes()==(root/(stem+'.rs')).read_bytes();got['rust_sha256']=sha(target)
  exe=d/stem;p=run(['rustc','--edition=2021',str(target),'-o',str(exe)]);assert p.returncode==0,p.stderr;actual=[]
  for expected in row['observations']:
   case=next(x for x in cases if x['name']==expected['name']);data=bytes.fromhex(case['input_hex']);path=d/'input.bin';path.write_bytes(data)
   if expected['kind']=='file':
    with path.open('rb') as f:p=run([str(exe)],stdin=f)
   else:p=run([str(exe)],input=data)
   obs=dict(kind=expected['kind'],name=expected['name'],exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex());assert obs==expected;actual.append(obs)
  path=d/'input.bin';path.write_bytes(b'a')
  with path.open('wb') as f:p=run([str(exe)],stdin=f)
  assert dict(exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex())==row['read_failure']
  path.write_bytes(b'a')
  with path.open('rb') as f,path.open('rb') as dest:p=run([str(exe)],stdin=f,stdout=dest)
  assert dict(exit=p.returncode,stderr_hex=p.stderr.hex(),destination_after_hex=path.read_bytes().hex())==row['write_failure']
  rd,wr=os.pipe();os.close(rd)
  with path.open('rb') as f,os.fdopen(wr,'wb',buffering=0) as dest:p=run([str(exe)],stdin=f,stdout=dest)
  assert dict(exit=p.returncode,stderr_hex=p.stderr.hex(),stdout='unobservable')==row['closedpipe_failure']
  # Separate substituted-backend executions of actual emitted code.
  (d/'generated.rs').write_bytes(target.read_bytes())
  harness=(Path(__file__).parent/'scripted_native.rs').read_text()
  payload=json.loads((Path(__file__).parent/'payload.json').read_text())['input_hex']
  harness=harness.replace('PAYLOAD',','.join(str(b) for b in bytes.fromhex(payload)))
  (d/'scripted.rs').write_text(harness)
  p=run(['rustc','--edition=2021',str(d/'scripted.rs'),'-o',str(d/'scripted')]);assert p.returncode==0,p.stderr
  p=run([str(d/'scripted')]);assert p.returncode==0 and not p.stderr,p.stderr
  records=[]
  for line in p.stdout.decode().splitlines():
   a,b,c,e,h=line.split(' ',4);records.append(dict(mode=int(a),exit=int(b),reads=int(c),writes=int(e),stdout_hex=h))
  expected=json.loads((Path(__file__).parent/'probe-expectations.json').read_text())[row['name']]
  assert len(records)==24
  for a,b in zip(records,expected):assert {k:a[k] for k in b}==b,(stem,a,b)
  got['scripted_backend']=records
  got.update(observations=actual,real_failures=3);rows.append(got)
(root/'native.json').write_text(json.dumps(rows,indent=2)+'\n');print(json.dumps([{k:v for k,v in r.items() if k not in ('observations','scripted_backend')} for r in rows],indent=2))
