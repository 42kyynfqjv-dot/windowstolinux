"""Build/run only the authored x86 observer with the pinned official CI compiler."""
from pathlib import Path
import hashlib, json, platform, shutil, struct, subprocess, sys
from api_set_namespace import CONTRACTS, SYMBOLS, validate
here=Path(__file__).resolve().parent
out=Path(sys.argv[1]).resolve();out.mkdir(parents=True,exist_ok=False)
source=here/'api_set_probe.c'; frozen=json.loads((here/'api-set-frozen.json').read_text())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(source)==frozen['source_sha256']
exe=out/'probe.exe'
command=['cl','/nologo','/W4','/O2','/GS',str(source),'/Fe'+str(exe),'/Fo'+str(out/'probe.obj')]
def run(command, timeout, log):
    try:
        p=subprocess.run(command,capture_output=True,timeout=timeout)
    except subprocess.TimeoutExpired as e:
        (out/log).write_bytes((e.stdout or b'')+(e.stderr or b''));raise
    (out/log).write_bytes(p.stdout+p.stderr)
    if p.returncode:raise ValueError(f'{log}: exit {p.returncode}')
    return p.stdout
run(command,60,'build.log')
def machine(p):
    data=p.read_bytes();at=struct.unpack_from('<I',data,60)[0]
    if data[at:at+4]!=b'PE\0\0':raise ValueError('PE signature')
    return struct.unpack_from('<H',data,at+4)[0]
report=dict(windows_version=list(map(int,platform.version().split('.'))),machine=machine(exe),
            source_sha256=sha(source),pe_sha256=sha(exe),command=command,
            compiler_path=shutil.which('cl'),compiler_sha256=sha(Path(shutil.which('cl'))),
            rows=[],translated_pairs=0)
for i,contract in enumerate(CONTRACTS):
    raw=run([str(exe),str(i)],15,f'case-{i}.log');row=json.loads(raw)
    row.update(contract=contract,symbol=SYMBOLS[i],flags=0x800)
    if row['loaded']:
        for field in ('load_host','export_host','ntdll'):
            path=Path(bytes.fromhex(row.pop(field+'_utf16')).decode('utf-16le'))
            # Path was resolved by a file handle inside the x86 observer. Do
            # not hash a same-named System32 DLL from this Python host instead.
            row[field]=dict(path=str(path),machine=machine(path),sha256=sha(path))
    report['rows'].append(row);(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
result=validate(report);(out/'validated.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(report))
