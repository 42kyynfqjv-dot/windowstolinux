"""Pinned Windows availability observations; no guessed availability oracle."""
from pathlib import Path
import hashlib
import json
import platform
import shutil
import struct
import subprocess
import sys

here = Path(__file__).resolve().parent
out = Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=False)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
frozen = json.loads((here / 'second-fiber-frozen-v2.json').read_text())
source = here / 'second_fiber_probe_v2.c'
if sha(source) != frozen['source_sha256']:
    raise ValueError('frozen observer source changed')
exe = out / 'second-fiber.exe'
command = ['cl', *frozen['flags'], str(source), '/Fe' + str(exe), '/Fo' + str(out / 'second-fiber.obj')]


def run(command, timeout, label):
    try:
        p = subprocess.run(command, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        (out / (label + '.stdout')).write_bytes(e.stdout or b'')
        (out / (label + '.stderr')).write_bytes(e.stderr or b'')
        raise
    (out / (label + '.stdout')).write_bytes(p.stdout)
    (out / (label + '.stderr')).write_bytes(p.stderr)
    if p.returncode:
        raise ValueError(f'{label} exited {p.returncode}')
    return p.stdout


run(command, 60, 'build')
b = exe.read_bytes()
pe = struct.unpack_from('<I', b, 60)[0]
if b[pe:pe+4] != b'PE\0\0' or struct.unpack_from('<H', b, pe+4)[0] != 0x14c:
    raise ValueError('x86 observer required')
rows = [json.loads(line) for line in run([str(exe)], 15, 'query').splitlines()]
for row in rows:
    if row['loaded']:
        path = Path(bytes.fromhex(row.pop('load_host_utf16')).decode('utf-16le'))
        row['load_host'] = dict(path=str(path), sha256=sha(path))
report = dict(kind=frozen['kind'], windows_version=platform.version(), source_sha256=sha(source), pe_sha256=sha(exe), command=command, compiler_path=shutil.which('cl'), compiler_sha256=sha(Path(shutil.which('cl'))), rows=rows)
(out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
if [row['candidate'] for row in rows] != [0, 1]:
    raise ValueError('candidate order/coverage')
for row in rows:
    if type(row['candidate']) is not int or any(type(row[key]) is not int or not 0 <= row[key] <= 0xffffffff for key in ('load_error', 'lookup_error')):
        raise ValueError('observation identity/error class')
    if any(type(row[key]) is not bool for key in ('loaded', 'found', 'released')):
        raise ValueError('observation result class')
    if row['loaded'] and not row['released'] or not row['loaded'] and (row['found'] or row['released']):
        raise ValueError('load/lookup/reference consistency')
# Availability and error values are measured, not assumed or used to tune code.
print(json.dumps(report))
