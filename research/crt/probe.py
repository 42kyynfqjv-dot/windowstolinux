"""Windows-only authored probes and separate unchanged-child observation."""
import hashlib,json,os,subprocess,tempfile
from pathlib import Path
repo=Path.cwd();root=Path(os.environ['RUNNER_TEMP'])/'w2l-compiler-measurement'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(args,**kw):return subprocess.run(args,capture_output=True,timeout=20,**kw)
for name in ['observer','exit_probe','initializer_probe']:
 p=run(['cl','/nologo','/W4','/O2',str(repo/'research/crt'/f'{name}.c'),f'/Fecrt_{name}.exe'],cwd=root)
 (root/f'crt-{name}-build.txt').write_bytes(p.stdout+p.stderr);assert p.returncode==0,(p.stdout,p.stderr)
child_env={k:v for k,v in os.environ.items() if k.upper() in ('SYSTEMROOT','WINDIR','TEMP','TMP','PATH','COMSPEC')}
results=[]
for mode in ['callbacks','buffer']:
 for end in ['normal','quick']:
  with tempfile.TemporaryDirectory(dir=root) as d:
   p=run([str(root/'crt_exit_probe.exe'),mode,end],cwd=d,env=child_env)
   markers=(Path(d)/'markers').read_bytes() if mode=='callbacks' else b''
   expected=(b'X' if mode=='buffer' and end=='normal' else b'', b'BA' if mode=='callbacks' and end=='normal' else b'')
   assert (p.returncode,p.stderr)==(0,b'') and (p.stdout,markers)==expected
   results.append(dict(mode=mode,end=end,stdout=p.stdout.hex(),markers=markers.hex(),exit=p.returncode))
initializer_results=[]
for arg,expected,code in [('0',b'ABCD',0),('1',b'A',7)]:
 with tempfile.TemporaryDirectory(dir=root) as d:
  p=run([str(root/'crt_initializer_probe.exe'),arg],cwd=d,env=child_env)
  assert (p.stdout,p.stderr,p.returncode)==(expected,b'',code)
  initializer_results.append(dict(arg=arg,stdout=p.stdout.hex(),exit=p.returncode))
pe=root/'held_crt.exe';before=sha(pe)
record=next(r for r in json.loads((root/'heldout-x86.json').read_text()) if r['kind']=='held_crt')
assert before==record['sha256'] and not record['conversion_accepted']
assert json.loads((root/'held_crt-baseline.json').read_text())==dict(stdout_hex='435254',stderr_hex='',exit=0,files={})
with tempfile.TemporaryDirectory(dir=root) as d:
 report=root/'crt-debug.txt'
 p=run([str(root/'crt_observer.exe'),str(pe),str(report)],cwd=d,env=child_env)
 assert (p.returncode,p.stdout,p.stderr)==(0,b'CRT',b'') and sha(pe)==before
# Missing child: exercise observer creation failure without spawning a process.
p=run([str(root/'crt_observer.exe'),str(root/'nonexistent-observer-child.exe'),str(root/'crt-missing-debug.txt')],env=child_env)
assert p.returncode==125
modules=[];base=None
for line in report.read_text().splitlines():
 fields=line.split('\t')
 if fields[0]=='BASE':base=int(fields[1]);continue
 path=fields[2];item=dict(base=int(fields[1]),path=path)
 if path!='UNRESOLVED':
  try:
   item['sha256']=sha(Path(path))
   # Path is data passed as an environment value, never interpolated into code.
   env=dict(os.environ,CRT_OBSERVED_PATH=path)
   v=run(['powershell','-NoProfile','-Command','(Get-Item -LiteralPath $env:CRT_OBSERVED_PATH).VersionInfo.FileVersion'],env=env)
   item['version']=v.stdout.decode(errors='replace').strip() if v.returncode==0 else None
  except OSError as e:item['error']=type(e).__name__
 modules.append(item)
assert base and modules
out=dict(pe_sha256=before,observer_sha256=sha(root/'crt_observer.exe'),probe_sha256=sha(root/'crt_exit_probe.exe'),
 source_sha256={n:sha(repo/'research/crt'/n) for n in ['observer.c','exit_probe.c','initializer_probe.c','probe.py']},
 initializer_probes=initializer_results,initializer_probe_sha256=sha(root/'crt_initializer_probe.exe'),probes=results,observed_base=base,modules=modules,observed_output=dict(stdout='435254',stderr='',exit=0),
 ordinary_baseline=json.loads((root/'held_crt-baseline.json').read_text()),separate_debug_run=True,emission_allowed=False)
(root/'crt-probes.json').write_text(json.dumps(out,indent=2)+'\n');print('CRT_PROBES',json.dumps(out))
