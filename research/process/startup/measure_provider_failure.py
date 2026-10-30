"""Authored attach-failure/owned-release observer in disposable CI output only."""
from pathlib import Path
import hashlib,json,platform,shutil,struct,subprocess,sys
from provider_failure import validate
here=Path(__file__).resolve().parent;out=Path(sys.argv[1]).resolve();out.mkdir(parents=True,exist_ok=False)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
frozen=json.loads((here/'provider-failure-frozen.json').read_text())
for name,digest in frozen['sources'].items():
    if sha(here/name)!=digest:raise ValueError('frozen source changed: '+name)
def run(command,limit,name):
    try:p=subprocess.run(command,capture_output=True,timeout=limit)
    except subprocess.TimeoutExpired as e:
        (out/name).write_bytes((e.stdout or b'')+(e.stderr or b''));raise
    (out/name).write_bytes(p.stdout+p.stderr)
    if p.returncode:raise ValueError(f'{name}: exit {p.returncode}')
    return p.stdout
commands=[]
for name,accepted in [('rejected',0),('accepted',1)]:
    command=['cl','/nologo','/W4','/O2','/MT','/LD',f'/DACCEPT_ATTACH={accepted}',str(here/'provider_attach.c'),'/Fe'+str(out/(name+'.dll')),'/Fo'+str(out/(name+'.obj')),'/link','/EXPORT:independent_value=_independent_value','/IMPLIB:'+str(out/(name+'.lib'))]
    commands.append(command);run(command,60,name+'-build.log')
exe=out/'observer.exe';command=['cl','/nologo','/W4','/O2','/MT',str(here/'provider_load_probe.c'),'/Fe'+str(exe),'/Fo'+str(out/'observer.obj')];commands.append(command);run(command,60,'observer-build.log')
for name in ('accepted.dll','rejected.dll','observer.exe'):
    b=(out/name).read_bytes();at=struct.unpack_from('<I',b,60)[0]
    if b[at:at+4]!=b'PE\0\0' or struct.unpack_from('<H',b,at+4)[0]!=0x14c:raise ValueError('x86 artifact required')
row=json.loads(run([str(exe),str(out/'rejected.dll'),str(out/'accepted.dll')],15,'observation.log'))
report=dict(kind='Original Windows authored DLL initialization failure; zero translations',windows_version=platform.version(),source_hashes=frozen['sources'],compiler_path=shutil.which('cl'),compiler_sha256=sha(Path(shutil.which('cl'))),commands=commands,artifacts={name:sha(out/name) for name in ('accepted.dll','rejected.dll','observer.exe')},observation=row)
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True)
validate(row)
if platform.version()!='10.0.20348':raise ValueError('unmeasured Windows host version')
