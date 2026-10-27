"""Frozen-source Windows baselines first, then converter measurement. No support edits."""
import hashlib,json,os,platform,subprocess,sys,time,re
from pathlib import Path
src=Path(__file__).resolve().parent;repo=src.parents[2];out=Path(sys.argv[1]).resolve();out.mkdir(parents=True,exist_ok=True)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n',encoding='utf-8')
def run(cmd,**kw):
 save(out/'stage.json',dict(command=list(map(str,cmd)),platform=platform.platform(),start=time.time()))
 try:return subprocess.run(cmd,timeout=30,**(dict(stderr=subprocess.PIPE) if 'stdout' in kw else dict(capture_output=True)),**kw)
 except subprocess.TimeoutExpired as e:
  save(out/'timeout.json',dict(command=list(map(str,cmd)),stdout=(e.stdout or b'').hex(),stderr=(e.stderr or b'').hex()));raise
m=json.loads((src/'frozen.json').read_text());cases=json.loads((src/'cases.json').read_text())
for f,h in m['sha256'].items():assert sha(src/f)==h
report=dict(manifest=m,platform=platform.platform(),programs=[])
for name in m['programs']:
 for cfg,flags in m['configurations'].items():
  stem=name+'_'+cfg;pe=out/(stem+'.exe');row=dict(name=name,config=cfg,observations=[]);report['programs'].append(row)
  cmds=[['cl']+m['compile_flags']+flags+[str(src/(name+'.c')),'/Fo'+stem+'.obj'],['link']+m['link_flags']+[stem+'.obj']+m['libraries']+['/out:'+stem+'.exe']]
  for i,cmd in enumerate(cmds):
   p=run(cmd,cwd=out);(out/(stem+'-build'+str(i)+'.txt')).write_bytes(p.stdout+p.stderr);assert p.returncode==0,p.stderr
  row.update(commands=cmds,pe_sha256=sha(pe),source_sha256=sha(src/(name+'.c')))
  for kind in ['disasm','headers','imports']:
   p=run(['dumpbin','/'+kind,str(pe)]);assert p.returncode==0;(out/(stem+'-'+kind+'.txt')).write_bytes(p.stdout)
  for kind in ['file','pipe']:
   for case in cases:
    data=bytes.fromhex(case['input_hex']);path=out/'input.bin';path.write_bytes(data)
    if kind=='file':
     with path.open('rb') as f:p=run([str(pe)],stdin=f)
    else:p=run([str(pe)],input=data)
    obs=dict(kind=kind,name=case['name'],exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex());row['observations'].append(obs);save(out/'report.json',report)
    assert (obs['exit'],obs['stdout_hex'],obs['stderr_hex'])==(0,case['expected'][name],'')
  path=out/'input.bin';path.write_bytes(b'a')
  with path.open('wb') as f:p=run([str(pe)],stdin=f)
  assert (p.returncode,p.stdout,p.stderr)==(11,b'',b'');row['read_failure']=dict(exit=11,stdout_hex='',stderr_hex='')
  path.write_bytes(b'a')
  with path.open('rb') as f,path.open('rb') as dest:p=run([str(pe)],stdin=f,stdout=dest)
  assert p.returncode==12 and not p.stderr and path.read_bytes()==b'a';row['write_failure']=dict(exit=12,stderr_hex='',destination_after_hex='61')
  rd,wr=os.pipe();os.close(rd)
  with path.open('rb') as f,os.fdopen(wr,'wb',buffering=0) as dest:p=run([str(pe)],stdin=f,stdout=dest)
  assert p.returncode==12 and not p.stderr;row['closedpipe_failure']=dict(exit=12,stderr_hex='',stdout='unobservable')
  save(out/'report.json',report)
# All original baselines and scripted probes finish before converter evaluation.
p=run(['cl']+m['probe_flags']+[str(src/'probe.c'),'/Fe:probe.exe'],cwd=out);(out/'probe-build.txt').write_bytes(p.stdout+p.stderr);assert p.returncode==0,p.stderr
p=run([str(out/'probe.exe')]);assert p.returncode==0 and not p.stderr
(out/'probe-output.txt').write_bytes(p.stdout)
records=[dict(mode=int(a),exit=int(b),reads=int(c),writes=int(d),stdout_hex=e) for a,b,c,d,e in re.findall(r'mode=(\d+) exit=(\d+) reads=(\d+) writes=(\d+) hex=([0-9a-f]*)',p.stdout.decode())]
expected=json.loads((src/'probe-expectations.json').read_text());assert len(records)==len(expected)==24
for a,b in zip(records,expected):assert {k:a[k] for k in b}==b,(a,b)
report['scripted_probe']=dict(kind='substituted backend, not original OS scheduling',records=records);save(out/'report.json',report)
for row in report['programs']:
 stem=row['name']+'_'+row['config'];pe=out/(stem+'.exe');target=out/(stem+'.rs');target.write_text('preserve')
 p=run([str(repo/'target/debug/w2l.exe'),str(pe),str(target)])
 row['conversion']=dict(exit=p.returncode,stderr=p.stderr.decode(errors='replace'))
 if p.returncode==0:row['conversion']['rust_sha256']=sha(target)
 else:assert p.returncode==1 and target.read_text()=='preserve'
 assert sha(pe)==row['pe_sha256'];save(out/'report.json',report)
print('2 untouched compiler artifacts;78 real Windows baselines;24 separately scripted backend cases;conversion outcomes recorded')

p=subprocess.run([sys.executable,str(src/'inventory.py'),str(out)],timeout=30);assert p.returncode==0
