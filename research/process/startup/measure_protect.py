"""Original Windows observer only; retains failure/timeout output without retry."""
from pathlib import Path
import hashlib
import json
import platform
import shutil
import struct
import subprocess
import sys
from protect_conformance import frozen, validate

here = Path(__file__).resolve().parent
out = Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=False)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
f = frozen()
exe = out / 'protect.exe'
command = ['cl', *f['flags'], str(here / 'protect_probe.c'), '/Fe' + str(exe), '/Fo' + str(out / 'protect.obj')]


def run(command, limit, name):
    try:
        p = subprocess.run(command, capture_output=True, timeout=limit)
    except subprocess.TimeoutExpired as e:
        (out / (name + '.stdout')).write_bytes(e.stdout or b'')
        (out / (name + '.stderr')).write_bytes(e.stderr or b'')
        raise
    (out / (name + '.stdout')).write_bytes(p.stdout)
    (out / (name + '.stderr')).write_bytes(p.stderr)
    if p.returncode:
        raise ValueError(f'{name}: exit {p.returncode}')
    return p.stdout


run(command, 60, 'build')
b = exe.read_bytes()
pe = struct.unpack_from('<I', b, 60)[0]
if b[pe:pe+4] != b'PE\0\0' or struct.unpack_from('<H', b, pe+4)[0] != 0x14c:
    raise ValueError('x86 observer required')
report = dict(kind=f['kind'], windows_version=platform.version(), source_sha256=f['source_sha256'], pe_sha256=sha(exe), compiler_path=shutil.which('cl'), compiler_sha256=sha(Path(shutil.which('cl'))), command=command, rows=[])
for mode in range(6):
    row = json.loads(run([str(exe), str(mode)], 15, f'case-{mode}'))
    report['rows'].append(row)
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    if row['mode'] != mode:
        raise ValueError('observer scenario mismatch')
    validate(row)
print(json.dumps(report))
