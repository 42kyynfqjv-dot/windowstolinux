"""Build/run one authored PE32 probe; retain raw rows before checking expectations."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

KIND = 'original Windows InitializeSListHead PE32 API observations; no PE translation'


def validate(raw):
    rows = [json.loads(line) for line in raw.splitlines()]
    if len(rows) != 13 or not all(isinstance(row, dict) for row in rows) or rows[0].get('kind') != KIND or rows[0].get('pointer_bytes') != 4 or rows[0].get('header_bytes') != 8:
        raise ValueError('SLIST probe target/layout/row count')
    for i, row in enumerate(rows[1:]):
        pattern, column = divmod(i, 3)
        offset = 16+8*column
        expected = [0]*8 if pattern == 0 else [255]*8 if pattern == 1 else [165]*8 if pattern == 2 else list(range(offset, offset+8))
        if (any(type(row.get(k)) is not int for k in ['case', 'pattern', 'offset', 'depth']) or row.get('case') != i or row.get('pattern') != pattern or row.get('offset') != offset
                or row.get('initial') != expected or row.get('depth') != 0
                or row.get('empty_pop_null') is not True or row.get('guards_unchanged') is not True):
            raise ValueError('SLIST independent input/logical/guard expectation')
        for key in ['initial', 'initialized', 'after_empty_pop']:
            if not isinstance(row.get(key), list) or len(row[key]) != 8 or any(type(n) is not int or not 0 <= n <= 255 for n in row[key]):
                raise ValueError('SLIST observed private bytes')
    return hashlib.sha256(raw).hexdigest()


def measure(output):
    if os.name != 'nt':
        raise ValueError('original SLIST observations require the authorized Windows/MSVC environment')
    output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).with_name('observe_slist.c').resolve()
    command = ['cl', '/nologo', '/W4', '/WX', '/O2', '/MT', str(source), '/Fe:slist.exe', '/link', '/MACHINE:X86', 'kernel32.lib']
    compiled = subprocess.run(command, cwd=output, capture_output=True, timeout=60)
    (output/'compile.stdout').write_bytes(compiled.stdout)
    (output/'compile.stderr').write_bytes(compiled.stderr)
    if compiled.returncode:
        raise ValueError('authored SLIST probe compilation failed; logs retained')
    executable = output/'slist.exe'
    try:
        run = subprocess.run([str(executable.resolve())], capture_output=True, timeout=15)
    except subprocess.TimeoutExpired as exc:
        (output/'original.stdout').write_bytes(exc.stdout or b'')
        (output/'original.stderr').write_bytes(exc.stderr or b'')
        raise
    (output/'original.stdout').write_bytes(run.stdout)
    (output/'original.stderr').write_bytes(run.stderr)
    if run.returncode:
        raise ValueError('original SLIST probe failed; raw output retained')
    digest = validate(run.stdout)
    report = dict(kind=KIND, source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(), pe_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(), observations_sha256=digest, cases=12, command=command, scope='Windows-host API observations; private bytes observational, no guest byte oracle or whole-PE pairs')
    (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    print(json.dumps(measure(args.output)))
