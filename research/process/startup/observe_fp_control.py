"""Build/run one authored PE32 probe; retain raw rows before checking expectations."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

KIND = 'Windows PE32 FP instruction observations'


def validate(raw):
    rows = [json.loads(line) for line in raw.splitlines()]
    if len(rows) != 13 or rows[0].get('kind') != KIND or rows[0].get('pointer_bytes') != 4:
        raise ValueError('FP probe target/row count')
    controls = [0x003f, 0x023f, 0x033f, 0x073f, 0x0b3f, 0x0f3f]
    for i, row in enumerate(rows[1:]):
        control = controls[i//2]
        mxcsr = 0x1f80 | (0x603f if i%2 else 0)
        expected = dict(case=i, input=control, output=control|0x40, status_defined=0,
                        mxcsr_in=mxcsr, mxcsr_out=mxcsr)
        if row != expected or any(type(v) is not int for v in row.values()):
            raise ValueError('FP defined-bit instruction expectation')
    return hashlib.sha256(raw).hexdigest()


def measure(output):
    if os.name != 'nt':
        raise ValueError('original FP observations require the authorized Windows/MSVC environment')
    output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).with_name('observe_fp_control.c').resolve()
    command = ['cl', '/nologo', '/W4', '/WX', '/O2', '/MT', str(source), '/Fe:fp_control.exe', '/link', '/MACHINE:X86', 'kernel32.lib']
    compiled = subprocess.run(command, cwd=output, capture_output=True, timeout=60)
    (output/'compile.stdout').write_bytes(compiled.stdout)
    (output/'compile.stderr').write_bytes(compiled.stderr)
    if compiled.returncode:
        raise ValueError('authored FP probe compilation failed; logs retained')
    executable = output/'fp_control.exe'
    try:
        run = subprocess.run([str(executable.resolve())], capture_output=True, timeout=15)
    except subprocess.TimeoutExpired as exc:
        (output/'original.stdout').write_bytes(exc.stdout or b'')
        (output/'original.stderr').write_bytes(exc.stderr or b'')
        raise
    (output/'original.stdout').write_bytes(run.stdout)
    (output/'original.stderr').write_bytes(run.stderr)
    if run.returncode:
        raise ValueError('original FP probe failed; raw output retained')
    digest = validate(run.stdout)
    report = dict(kind=KIND, source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(), pe_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(), observations_sha256=digest, cases=12, command=command, scope='Authored PE32 defined-bit ISA observations; no original-entry capture, no whole-PE pairs')
    (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    print(json.dumps(measure(args.output)))
