"""Unchanged third-party compiler baseline, then converter intake measurement."""
from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess,sys,time
here=Path(__file__).resolve().parent;repo=here.parents[1];out=Path(sys.argv[1]).resolve();payload=out/'payload';compiler=payload/'ISCC.exe';m=json.loads((here/'frozen.json').read_text());rows=[]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for name,digest in m['fixture_sha256'].items():assert sha(here/'fixtures'/name)==digest,(name,sha(here/'fixtures'/name),digest)
report=dict(platform=platform.platform(),scope='official prebuilt release; not source-rebuilt; no translated execution',compiler_sha256=sha(compiler),cases=rows)
def save(): (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
def run(args,stage,cwd=None):
 (out/'stage.json').write_text(json.dumps(dict(stage=stage,command=list(map(str,args)),cwd=str(cwd),start=time.time()),indent=2))
 try:return subprocess.run(list(map(str,args)),cwd=cwd,capture_output=True,timeout=60)
 except subprocess.TimeoutExpired as e:
  (out/'timeout.json').write_text(json.dumps(dict(stage=stage,command=list(map(str,args)),stdout=(e.stdout or b'').hex(),stderr=(e.stderr or b'').hex()),indent=2));raise
save()
# Complete every original observation before any converter invocation.
for case in m['cases']:
 for repeat in range(case['repeat']):
  work=out/'work'/(case['name']+str(repeat));work.mkdir(parents=True,exist_ok=False)
  for f in (here/'fixtures').iterdir():shutil.copy2(f,work/f.name)
  dest=work/'output';dest.mkdir()
  args=[compiler]+case.get('args',['/Q','/F'+case['name'],'/O'+str(dest),str(work/case.get('fixture',''))])
  p=run(args,case['name'],work);files=[dict(name=f.name,sha256=sha(f),bytes=f.stat().st_size,pe_signature=f.read_bytes().startswith(b'MZ')) for f in dest.iterdir() if f.is_file()]
  row=dict(case=case['name'],repeat=repeat,command=list(map(str,args)),exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex(),outputs=files);rows.append(row);save()
  assert p.returncode==case['exit'],row
  assert (len(files)==1 and files[0]['pe_signature']) if case['exit']==0 else not files,row
report['repeat_output_hashes_equal']={c['name']:rows[i]['outputs']==rows[i+1]['outputs'] for i,c in [(0,m['cases'][0]),(2,m['cases'][1])]};save()
# Full inventory includes original compiler DLLs; static listings are not runtime effect closure.
for f in sorted(payload.glob('*')):
 if f.suffix.lower() not in ['.exe','.dll']:continue
 for kind in (['headers','imports','disasm'] if f.name.lower() in ['iscc.exe','iscmplr.dll','ispp.dll'] else ['headers','imports']):
  p=run(['dumpbin','/'+kind,f],'inventory-'+f.name);assert p.returncode==0
  (out/(f.name+'-'+kind+'.txt')).write_bytes(p.stdout+p.stderr)
converter=repo/'target/debug/w2l.exe';target=out/'converted.rs';target.write_text('preserve');original_hash=sha(compiler)
p=run([converter,compiler,target],'conversion');report['conversion']=dict(exit=p.returncode,stdout_hex=p.stdout.hex(),stderr=p.stderr.decode(errors='replace'),sentinel_preserved=target.read_text()=='preserve');save()
assert sha(compiler)==original_hash==sha(out/'ISCC.exe')
assert p.returncode==1 and target.read_text()=='preserve','Unexpected admission requires dependency/effect review; not translation evidence'
p=run([converter,'--inspect-image',compiler],'inspection');report['inspection']=dict(exit=p.returncode,stdout=p.stdout.decode(errors='replace'),stderr=p.stderr.decode(errors='replace'));save()
print('Six original compiler observations and honest conversion rejection retained')
