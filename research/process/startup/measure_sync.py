"""Pinned authored Windows observations; no converted program execution."""
from pathlib import Path
import hashlib,json,platform,shutil,struct,subprocess,sys
from sync_conformance import validate
here=Path(__file__).resolve().parent
out=Path(sys.argv[1]).resolve();out.mkdir(parents=True,exist_ok=False)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
source=here/'sync_probe.c';frozen=json.loads((here/'sync-frozen.json').read_text())
if sha(source)!=frozen['source_sha256']:raise ValueError('frozen source changed')
exe=out/'sync.exe';command=['cl','/nologo','/W4','/O2','/GS',str(source),'/Fe'+str(exe),'/Fo'+str(out/'sync.obj')]
def run(command,limit,name):
    try:p=subprocess.run(command,capture_output=True,timeout=limit)
    except subprocess.TimeoutExpired as e:
        (out/name).write_bytes((e.stdout or b'')+(e.stderr or b''));raise
    (out/name).write_bytes(p.stdout+p.stderr)
    if p.returncode:raise ValueError(f'{name}: exit {p.returncode}')
    return p.stdout
run(command,60,'build.log')
b=exe.read_bytes();offset=struct.unpack_from('<I',b,60)[0]
if b[offset:offset+4]!=b'PE\0\0' or struct.unpack_from('<H',b,offset+4)[0]!=0x14c:raise ValueError('x86 observer required')
report=dict(kind='authored Windows synchronization observations; no translations',windows_version=platform.version(),source_sha256=sha(source),pe_sha256=sha(exe),compiler_path=shutil.which('cl'),compiler_sha256=sha(Path(shutil.which('cl'))),command=command,rows=[])
for spin in frozen['spins']:
    row=json.loads(run([str(exe),str(spin)],15,f'case-{spin}.log'));row['spin']=spin
    report['rows'].append(row);(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    validate(row)
print(json.dumps(report))
