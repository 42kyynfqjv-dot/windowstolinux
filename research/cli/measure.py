"""Windows-only original measurement; no converter support changes."""
import hashlib,json,os,platform,subprocess,sys,time
from pathlib import Path
src=Path(__file__).resolve().parent;repo=src.parents[1];out=Path(sys.argv[1]).resolve();out.mkdir(exist_ok=True,parents=True)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,d):p.write_text(json.dumps(d,indent=2)+'\n',encoding='utf-8')
def run(cmd,**kw):
 save(out/'stage.json',dict(command=list(map(str,cmd)),platform=platform.platform(),start=time.time()))
 try:return subprocess.run(cmd,capture_output=True,timeout=30,**kw)
 except subprocess.TimeoutExpired as e:
  save(out/'timeout.json',dict(command=list(map(str,cmd)),stdout=(e.stdout or b'').hex(),stderr=(e.stderr or b'').hex()));raise
m=json.loads((src/'frozen.json').read_text());cases=json.loads((src/'cases.json').read_text())
for name,h in m['sha256'].items():assert sha(src/name)==h
report=dict(manifest=m,platform=platform.platform(),programs=[])
for config,flags in m['configurations'].items():
 stem='uppercase_'+config;pe=out/(stem+'.exe');row=dict(config=config,observations=[]);report['programs'].append(row)
 commands=[['cl']+m['compile_flags']+flags+[str(src/'filter.c'),'/Fo'+stem+'.obj'],['link']+m['link_flags']+[stem+'.obj']+m['libraries']+['/out:'+stem+'.exe']]
 for index,cmd in enumerate(commands):
  p=run(cmd,cwd=out);(out/f'{stem}-build{index}.txt').write_bytes(p.stdout+p.stderr);assert p.returncode==0,p.stderr
 row.update(commands=commands,pe_sha256=sha(pe),source_sha256=sha(src/'filter.c'))
 for kind in ['disasm','headers','imports']:
  p=run(['dumpbin','/'+kind,str(pe)]);assert p.returncode==0;(out/f'{stem}-{kind}.txt').write_bytes(p.stdout)
 for v in cases:
  path=out/'input.bin';path.write_bytes(bytes.fromhex(v['input_hex']))
  with path.open('rb') as f:p=run([str(pe)],stdin=f)
  obs=dict(name=v['name'],exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex());row['observations'].append(obs)
  save(out/'report.json',report);assert obs=={k:v[k] for k in obs},obs
 # Closed anonymous-pipe EOF is a documented error for this frozen source.
 p=run([str(pe)],input=b'aZ\x00\xff');assert (p.returncode,p.stdout,p.stderr)==(11,b'AZ\x00\xff',b'')
 row['pipe_eof']=dict(exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex())
 path=out/'input.bin';path.write_bytes(b'a')
 with path.open('wb') as f:p=run([str(pe)],stdin=f)
 assert p.returncode==11 and p.stdout==b'';row['read_failure_exit']=p.returncode
 path.write_bytes(b'a')
 with path.open('rb') as f, (out/'input.bin').open('rb') as dest:
  p=subprocess.run([str(pe)],stdin=f,stdout=dest,stderr=subprocess.PIPE,timeout=30)
 assert p.returncode==12 and not p.stderr;row['write_failure_exit']=p.returncode
 target=out/(stem+'.rs');target.write_text('preserve')
 p=run([str(repo/'target/debug/w2l.exe'),str(pe),str(target)])
 assert p.returncode==1 and target.read_text()=='preserve'
 row['conversion']=dict(accepted=False,error=p.stderr.decode());assert sha(pe)==row['pe_sha256'];save(out/'report.json',report)
p=run(['cl','/nologo','/W4','/O2',str(src/'probe.c'),'/Fe:probe.exe'],cwd=out);(out/'probe-build.txt').write_bytes(p.stdout+p.stderr);assert p.returncode==0
p=run([str(out/'probe.exe')]);assert p.returncode==0;pout=p.stdout.decode();(out/'probe-results.txt').write_text(pout)
report['scripted_probe']=dict(cases=8,source_sha256=sha(src/'probe.c'),kind='substituted API backend, not original program baseline');save(out/'report.json',report)
print('CLI MEASUREMENT:2 unchanged PEs;22 regular-file cases;2 pipe EOF cases;4 real I/O failures;8 scripted API cases;production rejected')
