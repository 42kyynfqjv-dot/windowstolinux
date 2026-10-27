"""Same hashed PE and emitted Rust, accepted executions or exact rejection evidence."""
import hashlib,json,os,subprocess,sys,tempfile
from pathlib import Path
root=Path(sys.argv[1]).resolve();repo=Path(__file__).resolve().parents[3];report=json.loads((root/'report.json').read_text());src=Path(__file__).resolve().parent.parent/'stateful';cases=json.loads((src/'cases.json').read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(cmd,**kw):return subprocess.run(cmd,timeout=30,**(dict(stderr=subprocess.PIPE) if 'stdout' in kw else dict(capture_output=True)),**kw)
rows=[]
with tempfile.TemporaryDirectory() as td:
 d=Path(td)
 for row in report['programs']:
  if 'build_failure' in row:rows.append(dict(name=row['name'],config=row['config'],build_failure=row['build_failure']));continue
  stem=row['name']+'_'+row['config'];pe=root/(stem+'.exe');target=d/(stem+'.rs');target.write_text('preserve');assert sha(pe)==row['pe_sha256']
  p=run([str(repo/'target/debug/w2l'),str(pe),str(target)]);c=row['conversion'];assert p.returncode==c['exit']
  got=dict(name=row['name'],config=row['config'],pe_sha256=sha(pe),conversion_exit=p.returncode,stderr=p.stderr.decode(errors='replace'))
  if p.returncode:
   assert p.returncode==1 and target.read_text()=='preserve'
   def budget(t):return 'wall-time budget exhausted' in t or 'max. resource limit exceeded' in t
   assert got['stderr']==c['stderr'] or (budget(got['stderr']) and budget(c['stderr'])),(stem,got['stderr'],c['stderr'])
   got.update(windows_stderr=c['stderr'],diagnostic_text_equal=got['stderr']==c['stderr'],rejection_class='proof-budget' if budget(got['stderr']) else 'exact-diagnostic');rows.append(got);continue
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
  got.update(observations=actual,real_failures=3);rows.append(got)
(root/'native.json').write_text(json.dumps(rows,indent=2)+'\n');print(json.dumps([{k:v for k,v in r.items() if k not in ('observations','scripted_backend')} for r in rows],indent=2))
