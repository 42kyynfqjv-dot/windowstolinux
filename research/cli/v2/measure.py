"""Windows-only original measurement; no converter support changes."""
import hashlib,json,os,platform,re,subprocess,sys,time
from pathlib import Path
src=Path(__file__).resolve().parent;repo=src.parents[2];out=Path(sys.argv[1]).resolve();out.mkdir(exist_ok=True,parents=True)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,d):p.write_text(json.dumps(d,indent=2)+'\n',encoding='utf-8')
def run(cmd,**kw):
 save(out/'stage.json',dict(command=list(map(str,cmd)),platform=platform.platform(),start=time.time()))
 try:return subprocess.run(cmd,timeout=30,**(dict(stderr=subprocess.PIPE) if "stdout" in kw else dict(capture_output=True)),**kw)
 except subprocess.TimeoutExpired as e:
  save(out/'timeout.json',dict(command=list(map(str,cmd)),stdout=(e.stdout or b'').hex(),stderr=(e.stderr or b'').hex()));raise
m=json.loads((src/'frozen.json').read_text());cases=json.loads((src/'cases.json').read_text())
for name,h in m['sha256'].items():assert sha(src/name)==h,(name,sha(src/name),h)
expected=json.loads((src/'expectations.json').read_text())
extra=json.loads((src/'extra-failures.json').read_text())
report=dict(manifest=m,platform=platform.platform(),programs=[])
for config,flags in m['configurations'].items():
 stem='uppercase_v2_'+config;pe=out/(stem+'.exe');row=dict(config=config,observations=[]);report['programs'].append(row)
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
 # Same independently frozen byte expectations, now with pipeline-success EOF.
 row['pipe_observations']=[]
 for v in cases:
  p=run([str(pe)],input=bytes.fromhex(v['input_hex']))
  obs=dict(name=v['name'],exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex())
  row['pipe_observations'].append(obs);save(out/'report.json',report)
  assert obs=={k:v[k] for k in obs},obs
 path=out/'input.bin';path.write_bytes(b'a')
 with path.open('wb') as f:p=run([str(pe)],stdin=f)
 assert (p.returncode,p.stdout,p.stderr)==(11,b'',b'');row['read_failure_exit']=p.returncode
 row['read_failure']=dict(exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex())
 path.write_bytes(b'a')
 with path.open('rb') as f, (out/'input.bin').open('rb') as dest:
  p=run([str(pe)],stdin=f,stdout=dest)
 assert p.returncode==12 and not p.stderr;row['write_failure_exit']=p.returncode
 row['write_failure']=dict(exit=p.returncode,destination_after_hex=path.read_bytes().hex(),stderr_hex=p.stderr.hex());assert path.read_bytes()==b'a'
 # Close read endpoint BEFORE process creation: no race-dependent pipe consumer.
 closed=extra['closed_output_pipe'];path.write_bytes(bytes.fromhex(closed['input_hex']))
 rd,wr=os.pipe();os.close(rd)
 with path.open('rb') as f, os.fdopen(wr,'wb',buffering=0) as dest:
  p=run([str(pe)],stdin=f,stdout=dest)
 row['closed_output_pipe']=dict(exit=p.returncode,stderr_hex=p.stderr.hex(),stdout=closed['stdout'])
 assert p.returncode==closed['exit'] and p.stderr.hex()==closed['stderr_hex']
 target=out/(stem+'.rs');target.write_text('preserve')
 p=run([str(repo/'target/debug/w2l.exe'),str(pe),str(target)])
 assert p.returncode==1 and target.read_text()=='preserve'
 row['conversion']=dict(accepted=False,error=p.stderr.decode());assert sha(pe)==row['pe_sha256'];save(out/'report.json',report)
p=run(['cl','/nologo','/W4','/O2',str(src/'probe.c'),'/Fe:probe.exe'],cwd=out);(out/'probe-build.txt').write_bytes(p.stdout+p.stderr);assert p.returncode==0
p=run([str(out/'probe.exe')]);assert p.returncode==0;pout=p.stdout.decode();(out/'probe-results.txt').write_text(pout)
records=[dict(mode=int(a),exit=int(b),reads=int(c),writes=int(d),output_bytes=int(e)) for a,b,c,d,e in re.findall(r'mode=(\d+) exit=(\d+) read_calls=(\d+) write_calls=(\d+) output_bytes=(\d+)',pout)]
assert [r['mode'] for r in records]==list(range(10)) and [r['exit'] for r in records]==expected['scripted_exits']
report['extra_failure_sha256']=sha(src/'extra-failures.json')
report['scripted_probe']=dict(cases=len(records),records=records,source_sha256=sha(src/'probe.c'),kind='substituted API backend, not original program baseline');save(out/'report.json',report)
print('CLI V2:2 unchanged PEs;28 regular-file cases;28 pipe cases;6 real I/O failures;10 scripted API cases;production rejected')
