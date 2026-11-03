"""Frozen architectural counterexample; original Windows evidence only."""
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys

here = Path(__file__).resolve().parent
sys.path.insert(0, str(here.parents[2]/'corpus'))
from launch import execute

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main(out):
    frozen = json.loads((here/'context-frozen.json').read_text())
    source = here/'context_probe.c'
    if digest(source) != frozen['source_sha256']:
        raise ValueError('frozen source identity changed')
    out.mkdir(parents=True, exist_ok=False)
    exe = out/'context.exe'
    command = ['cl', '/nologo', '/W4', '/O2', '/GS', str(source),
               '/Fe'+str(exe), '/Fo'+str(out/'context.obj')]
    build = subprocess.run(command, capture_output=True, timeout=60)
    (out/'build.txt').write_bytes(build.stdout+build.stderr)
    if build.returncode: raise RuntimeError('context probe compilation failed')
    disasm = subprocess.run(['dumpbin', '/disasm', str(exe)], capture_output=True, timeout=60)
    (out/'disasm.txt').write_bytes(disasm.stdout+disasm.stderr)
    if disasm.returncode: raise RuntimeError('context probe disassembly failed')
    pe_hash = digest(exe)
    report = dict(kind='original Windows context/nonlocal observations; zero translated pairs',
                  platform=platform.platform(), command=command,
                  source_sha256=digest(source), pe_sha256=pe_hash,
                  compiler_sha256=digest(Path(shutil.which('cl'))), observations=[])
    for case in frozen['cases']:
        stdout, stderr = out/(case['mode']+'.out'), out/(case['mode']+'.err')
        result = execute([str(exe), case['mode']], stdout, stderr,
                         out/(case['mode']+'-launch'), {'case':case['mode']}, case, timeout=10)
        row = dict(mode=case['mode'], exit=result.returncode,
                   stdout_hex=stdout.read_bytes().hex(), stderr_hex=stderr.read_bytes().hex())
        report['observations'].append(row)
        (out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
        if row != case: raise RuntimeError('frozen context observation mismatch')
        if digest(exe) != pe_hash: raise RuntimeError('executed image identity changed')
    print(json.dumps(report, indent=2))

if __name__ == '__main__': main(Path(sys.argv[1]).resolve())
