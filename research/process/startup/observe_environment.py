"""Build/run one authored PE32 probe; retain raw rows before checking expectations."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

KIND = 'Synthetic-only PE32 process environment observations'


def validate(raw):
    rows = [json.loads(x) for x in raw.splitlines()]
    if len(rows) != 2:
        raise ValueError('environment observation row count')
    for row, name, count in zip(rows, ['synthetic', 'empty'], [3, 0]):
        if type(row.get('entries')) is not int or type(row.get('units')) is not int or row.get('case') != name or row.get('entries') != count or row.get('units') != (sum(len(s.encode('utf-16le'))//2+1 for s in ['W2L_ALPHA=one', 'W2L_EMPTY=', 'W2L_UNICODE=雪😀'])+1 if name=='synthetic' else 2):
            raise ValueError('controlled environment layout mismatch')
        if not all(row.get(k) is True for k in ['distinct_live', 'stable_after_mutation', 'free_first', 'free_second']):
            raise ValueError('environment copy/lifetime observation mismatch')
    return hashlib.sha256(raw).hexdigest()


def measure(output):
    if os.name != 'nt':
        raise ValueError('original environment observations require the authorized Windows/MSVC environment')
    output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).with_name('observe_environment.c').resolve()
    command = ['cl', '/nologo', '/W4', '/WX', '/O2', '/MT', '/utf-8', str(source), '/Fe:environment.exe', '/link', '/MACHINE:X86', 'kernel32.lib']
    compiled = subprocess.run(command, cwd=output, capture_output=True, timeout=60)
    (output/'compile.stdout').write_bytes(compiled.stdout)
    (output/'compile.stderr').write_bytes(compiled.stderr)
    if compiled.returncode:
        raise ValueError('authored environment probe compilation failed; logs retained')
    executable = output/'environment.exe'
    # The child receives ONLY these known synthetic entries. Never record the
    # worker's real environment, even on unexpected output or failure.
    all_raw = b''
    for label, environment in [('synthetic', {'W2L_ALPHA': 'one', 'W2L_EMPTY': '', 'W2L_UNICODE': '雪😀'}), ('empty', {})]:
        try:
            run = subprocess.run([str(executable.resolve()), label], env=environment,
                                 capture_output=True, timeout=15)
        except subprocess.TimeoutExpired:
            (output/(label+'-failure.txt')).write_text('controlled child timeout; no environment contents retained\n')
            raise
        (output/(label+'.stdout')).write_bytes(run.stdout)
        (output/(label+'.stderr')).write_bytes(run.stderr)
        if run.returncode:
            raise ValueError('synthetic environment probe failed; controlled diagnostics retained')
        all_raw += run.stdout
    (output/'original.stdout').write_bytes(all_raw)
    digest = validate(all_raw)
    report = dict(kind=KIND, source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(), pe_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(), observations_sha256=digest, cases=2, command=command, scope='Controlled child environment only; no host propagation or failed-API equivalence, no whole-PE pairs')
    (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    print(json.dumps(measure(args.output)))
