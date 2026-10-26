"""Bounded original-only launch probe; every sample is mandatory, never a retry."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

from imported_fixture import fixture
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'corpus'))
from generate import build

assert sys.platform == 'win32', 'Windows baseline required'
root = Path(os.environ['RUNNER_TEMP']) / 'w2l-launch-diagnosis'
root.mkdir(exist_ok=True)
cases = [('max', fixture(b'A'*64), b'A'*64),
         ('corpus14', build(14), b'C14'), ('hello', fixture(b'Hello'), b'Hello')]
records = []
for mode in ['reused', 'fresh']:
    for repetition in range(3):
        for name, image, expected in cases:
            exe = root / ('reused.exe' if mode == 'reused' else f'{name}-{repetition}.exe')
            exe.write_bytes(image)
            stdout, stderr = root/'stdout', root/'stderr'
            record = dict(case=name, mode=mode, repetition=repetition,
                          pe_sha256=hashlib.sha256(image).hexdigest(), os=platform.platform())
            print('launch probe starting '+json.dumps(record), flush=True)
            start = time.perf_counter()
            with stdout.open('wb') as out, stderr.open('wb') as err:
                process = subprocess.Popen([str(exe)], stdout=out, stderr=err)
                record.update(pid=process.pid, spawn_seconds=time.perf_counter()-start)
                try:
                    record['exit'] = process.wait(timeout=15)
                    record['timeout'] = False
                except subprocess.TimeoutExpired:
                    record['timeout'] = True
                    process.kill()
                    record['exit'] = process.wait(timeout=5)
            record.update(elapsed_seconds=time.perf_counter()-start,
                          stdout_hex=stdout.read_bytes().hex(), stderr_hex=stderr.read_bytes().hex())
            record['passed'] = (not record['timeout'] and record['exit']==0
                                and stdout.read_bytes()==expected and not stderr.read_bytes())
            records.append(record)
            (root/'report.json').write_text(json.dumps(records, indent=2)+'\n')
            # Preserve the exact legal fixture associated with any failure.
            if not record['passed']:
                (root/f'failed-{len(records)}.exe').write_bytes(image)
            print('launch probe result '+json.dumps(record), flush=True)
assert len(records)==18 and all(r['passed'] for r in records), 'launch probe failed; see report.json'
