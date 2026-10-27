"""Frozen-source Windows baselines first, then mandatory integrated conversion."""
import hashlib,json,os,platform,subprocess,sys,time,re
from pathlib import Path
here=Path(__file__).resolve().parent;src=here.parent/"stateful";repo=src.parents[2];out=Path(sys.argv[1]).resolve();out.mkdir(parents=True,exist_ok=True)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n',encoding='utf-8')
def run(cmd,**kw):
 save(out/'stage.json',dict(command=list(map(str,cmd)),platform=platform.platform(),start=time.time()))
 try:return subprocess.run(cmd,timeout=30,**(dict(stderr=subprocess.PIPE) if 'stdout' in kw else dict(capture_output=True)),**kw)
 except subprocess.TimeoutExpired as e:
  import shutil
  if Path(cmd[0]).is_file():shutil.copyfile(cmd[0],out/'timeout-program.bin')
  save(out/'timeout.json',dict(command=list(map(str,cmd)),stdout=(e.stdout or b'').hex(),stderr=(e.stderr or b'').hex()));raise
m=json.loads((here/'frozen.json').read_text());cases=json.loads((src/'cases.json').read_text())
for f,h in m['sha256'].items():assert sha(src/f)==h,(f,sha(src/f),h)
import shutil
compiler=Path(os.environ['W2L_CLANG_CL']).resolve();linker=Path(shutil.which('link.exe')).resolve()
p=run([str(compiler),'--version']);assert p.returncode==0 and 'clang version '+m['toolchain_version'] in p.stdout.decode()
report=dict(manifest=m,platform=platform.platform(),toolchain=dict(compiler=str(compiler),compiler_sha256=sha(compiler),compiler_version=p.stdout.decode(),linker=str(linker),linker_sha256=sha(linker),sdk_version=os.environ.get('WindowsSDKVersion'),sdk_dir=os.environ.get('WindowsSdkDir')),programs=[])
save(out/'report.json',report)
for name in m['programs']:
 for cfg,flags in m['configurations'].items():
  stem=name+'_'+cfg;pe=out/(stem+'.exe');row=dict(name=name,config=cfg,observations=[]);report['programs'].append(row)
  cmds=[[str(compiler)]+m['compile_flags']+flags+[str(src/(name+'.c')),'/Fo'+stem+'.obj'],['link']+m['link_flags']+[stem+'.obj']+m['libraries']+['/out:'+stem+'.exe']]
  row['commands']=cmds
  build_ok=True
  for i,cmd in enumerate(cmds):
   p=run(cmd,cwd=out);(out/(stem+'-build'+str(i)+'.txt')).write_bytes(p.stdout+p.stderr);
   if p.returncode: row['build_failure']=dict(stage=i,exit=p.returncode);build_ok=False;break
  if not build_ok:save(out/'report.json',report);continue
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
# Every available original baseline finishes before converter evaluation.
for row in report['programs']:
 if 'build_failure' in row:continue
 stem=row['name']+'_'+row['config'];pe=out/(stem+'.exe');target=out/(stem+'.rs');target.write_text('preserve')
 p=run([str(repo/'target/debug/w2l.exe'),str(pe),str(target)])
 row['conversion']=dict(exit=p.returncode,stderr=p.stderr.decode(errors='replace'))
 if p.returncode==0:row['conversion']['rust_sha256']=sha(target)
 else:assert p.returncode==1 and target.read_text()=='preserve'
 assert sha(pe)==row['pe_sha256'];save(out/'report.json',report)
print('LLVM measurement: builds/baselines/conversion outcomes retained in report.json')

p=subprocess.run([sys.executable,str(here/'inventory.py'),str(out)],timeout=30);assert p.returncode==0
