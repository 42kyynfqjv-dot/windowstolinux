"""Frozen unchanged upstream build, independent original observations, honest intake."""
from pathlib import Path
import hashlib,json,os,platform,shutil,struct,subprocess,sys,time
from pe_resources import snapshot
here=Path(__file__).resolve().parent;repo=here.parents[2];out=Path(sys.argv[1]).resolve();out.mkdir(parents=True,exist_ok=False);m=json.loads((here/'frozen.json').read_text());rows=[]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
report=dict(platform=platform.platform(),frozen_sha256=sha(here/'frozen.json'),source_commit=m['source_commit'],scope='unmodified source-built utility; no translated execution',commands=[],cases=rows)
def save(): (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
def run(args,stage,cwd=None,allow_failure=False):
 args=list(map(str,args));record=dict(stage=stage,command=args,cwd=str(cwd),started=time.time());report['commands'].append(record);save()
 try:p=subprocess.run(args,cwd=cwd,capture_output=True,timeout=120 if stage.startswith(('source','configure','build')) else 30)
 except subprocess.TimeoutExpired as e:
  record.update(timeout=True,stdout_hex=(e.stdout or b'').hex(),stderr_hex=(e.stderr or b'').hex());save();raise
 record.update(exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex());save()
 if not allow_failure:assert p.returncode==0,(stage,p.stderr)
 return p
for name,digest in m['fixtures'].items():assert sha(here/'fixtures'/name)==digest,name
# Fingerprint existing installed tools BEFORE building; never replace after failure.
report['toolchain']={}
for name in ['cl.exe','link.exe','rc.exe','nmake.exe','cmake.exe']:
 path=shutil.which(name);report['toolchain'][name]=dict(path=path,sha256=sha(Path(path)) if path else None);save()
 assert path,('missing existing build prerequisite',name)
report['toolchain']['sdk_version']=os.environ.get('WindowsSDKVersion');report['build_cohorts']=m['build_cohorts'];save()
assert '/'+m['toolset_selection']+'.' in report['toolchain']['cl.exe']['path'].replace('\\','/'),'require frozen preinstalled toolset'
report['toolchain']['installed_msvc_directories']=[p.name for p in Path(report['toolchain']['cl.exe']['path']).parents[4].iterdir() if p.is_dir()];save()
run(['cl.exe','/Bv'],'compiler-version',allow_failure=True);run(['cmake','--version'],'cmake-version');run(['link.exe'],'linker-version',allow_failure=True)
source=out/'source';run(['git','init',source],'source-init')
run(['git','-C',source,'-c','core.autocrlf=false','fetch','--depth=1',m['source_repository'],m['source_commit']],'source-fetch')
run(['git','-C',source,'-c','core.autocrlf=false','checkout','--detach','FETCH_HEAD'],'source-checkout')
actual=run(['git','-C',source,'rev-parse','HEAD'],'source-identity').stdout.decode().strip();assert actual==m['source_commit']
paths=run(['git','-C',source,'ls-files','-z'],'source-files').stdout.decode().split('\0');report['source_files']={name:sha(source/name) for name in paths if name};save()
for name,blob in json.loads((here/'source-pins.json').read_text()).items():
 actual=run(['git','-C',source,'hash-object','--no-filters',name],'source-blob').stdout.decode().strip();assert actual==blob,(name,actual,blob)
shutil.copy2(source/'LICENSE',out/'LICENSE-rcedit.txt')
build=out/'build';run(['cmake','-S',source,'-B',build,'-G',m['generator'],'-DCMAKE_BUILD_TYPE='+m['configuration']],'configure-upstream')
run(['cmake','--build',build,'--config',m['configuration'],'--verbose'],'build-upstream')
utility=build/'rcedit.exe';assert utility.is_file();shutil.copy2(utility,out/'rcedit.exe');report['utility_sha256']=sha(utility);ub=utility.read_bytes();up=struct.unpack_from('<I',ub,60)[0];assert struct.unpack_from('<H',ub,up+4)[0]==0x14c,'require frozen x86 target';save()
fixture=out/'fixture';fixture.mkdir()
for f in (here/'fixtures').iterdir():shutil.copy2(f,fixture/f.name)
run(['rc','/nologo','/fofixture.res','fixture.rc'],'build-fixture-resources',fixture)
run(['cl','/nologo','/W4','/O2','fixture.c','fixture.res','/Fefixture.exe'],'build-fixture',fixture)
run(['cl','/nologo','/W4','/O2','observe.c','/Feobserve.exe','/link','version.lib'],'build-observer',fixture)
original=fixture/'fixture.exe';observer=fixture/'observe.exe';initial=original.read_bytes();baseline=snapshot(initial)
def observe(path):
 p=run([observer,path],'independent-observation');return dict(line.split('=',1) for line in p.stdout.decode('ascii').splitlines())
assert observe(original)==m['base_observer'];report['fixture_sha256']=sha(original);report['base_snapshot']=baseline;save()
# All original utility semantics are measured before converter evaluation.
for case in m['cases']:
 work=out/'cases'/case['name'];work.mkdir(parents=True);target=work/'target.exe';target.write_bytes(b'not-a-PE' if case.get('malformed') else initial)
 before=target.read_bytes();args=[str(fixture/'replacement.bin') if x=='{replacement}' else x for x in case['args']]
 p=run([utility,target]+args,case['name'],work,allow_failure=True)
 row=dict(name=case['name'],exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex(),before_sha256=hashlib.sha256(before).hexdigest(),after_sha256=sha(target));rows.append(row);save()
 assert p.returncode==case['exit'],row
 if 'stdout' in case:assert p.stdout==case['stdout'].encode('ascii'),row
 if case['exit']==0:assert not p.stderr,row
 if not case['mutates']:assert target.read_bytes()==before,row
 if not case.get('malformed'):
  row['observed']=observe(target);row['snapshot']=snapshot(target.read_bytes());save()
  expected=dict(m['base_observer']);expected.update(case.get('expected',{}));assert row['observed']==expected,row
  for field in ['machine','entry','code_sha256']:assert row['snapshot'][field]==baseline[field],(case['name'],field)
  # Version serializers may normalize metadata; semantic values above are the
  # independent oracle. Privilege manifests must remain byte-identical.
  manifests={k:v for k,v in baseline['resources'].items() if k.startswith('24/')}
  assert {k:v for k,v in row['snapshot']['resources'].items() if k.startswith('24/')}==manifests
assert sha(original)==report['fixture_sha256'] and sha(utility)==report['utility_sha256']
for kind in ['headers','imports','disasm']:
 p=run(['dumpbin','/'+kind,utility],'inventory-'+kind);(out/('rcedit-'+kind+'.txt')).write_bytes(p.stdout+p.stderr)
converter=repo/'target/debug/w2l.exe';target=out/'converted.rs';target.write_text('preserve');p=run([converter,utility,target],'conversion',allow_failure=True)
report['conversion']=dict(exit=p.returncode,stderr=p.stderr.decode(errors='replace'),sentinel_preserved=target.read_text()=='preserve');save()
assert p.returncode==1 and target.read_text()=='preserve','Unexpected admission needs full runtime/resource-effect review, not automatic acceptance'
p=run([converter,'--inspect-image',utility],'inspection',allow_failure=True);report['inspection']=dict(exit=p.returncode,stdout=p.stdout.decode(errors='replace'),stderr=p.stderr.decode(errors='replace'));save()
assert sha(utility)==report['utility_sha256'];print('Original source-built utility observations retained; zero third-party ELF pairs')
