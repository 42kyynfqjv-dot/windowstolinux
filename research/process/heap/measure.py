"""Original Windows observations then untouched converter measurement, no retries."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO / 'corpus'))
from launch import capture_process_state


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def run(command, evidence, *, stdin=None, stdout=None, cwd=None, timeout=15):
    evidence.mkdir(parents=True, exist_ok=True)
    record = dict(command=list(map(str, command)), platform=platform.platform(),
                  timeout_seconds=timeout, timeout=False, started=time.time())
    executable = Path(command[0])
    if executable.is_file():
        record['executed_sha256'] = sha(executable)
    save(evidence / 'launch.json', record)
    with (evidence / 'stdout').open('wb') as out, (evidence / 'stderr').open('wb') as err:
        start = time.perf_counter()
        child = subprocess.Popen(command, stdin=stdin, stdout=out if stdout is None else stdout, stderr=err, cwd=cwd)
        record.update(pid=child.pid, spawn_seconds=time.perf_counter()-start)
        save(evidence / 'launch.json', record)
        try:
            record['exit'] = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            record.update(timeout=True, poll_at_timeout=child.poll())
            save(evidence / 'launch.json', record)
            if executable.is_file():
                shutil.copyfile(executable, evidence / 'program.bin')
            record['process_state'] = capture_process_state(child.pid, evidence)
            if child.poll() is None:
                child.kill()
                record['exit_after_kill'] = child.wait(timeout=5)
            else:
                record['exit_during_diagnostics'] = child.wait(timeout=5)
            raise
        finally:
            record['elapsed_seconds'] = time.perf_counter()-start
            save(evidence / 'launch.json', record)
    record.update(stdout_hex=(evidence/'stdout').read_bytes().hex(), stderr_hex=(evidence/'stderr').read_bytes().hex())
    save(evidence / 'launch.json', record)
    return record


def main():
    out = Path(sys.argv[1]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((HERE / 'frozen.json').read_text())
    cases = json.loads((HERE / 'cases.json').read_text())
    for name, digest in manifest['sha256'].items():
        assert sha(HERE / name) == digest, name
    report = dict(manifest=manifest, platform=platform.platform(), programs=[],
                  toolchain={key: os.environ.get(key) for key in ['VCToolsVersion', 'WindowsSDKVersion']})
    for tool in ['cl.exe', 'link.exe']:
        path = Path(shutil.which(tool))
        report['toolchain'][tool] = dict(path=str(path), sha256=sha(path))
    for name in manifest['programs']:
        pe = out / (name + '.exe')
        row = dict(name=name, source_sha256=sha(HERE / (name + '.c')), observations=[])
        report['programs'].append(row)
        commands = [
            ['cl'] + manifest['compile_flags'] + manifest['configurations']['O2'] + [str(HERE/(name+'.c')), '/Fo'+name+'.obj'],
            ['link'] + manifest['link_flags'] + [name+'.obj'] + manifest['libraries'] + ['/out:'+name+'.exe'],
        ]
        row['commands'] = commands
        for i, command in enumerate(commands):
            r = run(command, out / (name+'-build-'+str(i)), cwd=out, timeout=30)
            assert r['exit'] == 0, r
        row['pe_sha256'] = sha(pe)
        for kind in ['headers', 'imports', 'disasm']:
            r = run(['dumpbin', '/'+kind, str(pe)], out/(name+'-'+kind), timeout=30)
            assert r['exit'] == 0
        for case in cases:
            source = out/'input.bin'
            source.write_bytes(bytes.fromhex(case['input_hex']))
            with source.open('rb') as stream:
                r = run([str(pe)], out/(name+'-'+case['name']), stdin=stream)
            row['observations'].append(dict(name=case['name'], **r))
            save(out/'report.json', report)
            assert (r['exit'], r['stdout_hex'], r['stderr_hex']) == (0, case['expected'][name], '')
        # Real file-handle failure observations, not huge allocations or unsafe reads.
        source = out/'input.bin'
        with source.open('wb') as stream:
            r = run([str(pe)], out/(name+'-read-error'), stdin=stream)
        row['read_failure'] = r
        assert (r['exit'],r['stdout_hex'],r['stderr_hex']) == (11,'','')
        source.write_bytes(b'\x1f\x0f')
        with source.open('rb') as stream, source.open('rb') as destination:
            r = run([str(pe)], out/(name+'-write-error'), stdin=stream, stdout=destination)
        row['write_failure'] = r
        assert (r['exit'],r['stderr_hex']) == (14,'') and source.read_bytes() == b'\x1f\x0f'
        save(out/'report.json', report)
    # Queries only AFTER every independently expected Windows observation.
    for row in report['programs']:
        name = row['name']
        pe = out/(name+'.exe')
        rust = out/(name+'.rs')
        rust.write_text('preserve', encoding='utf-8')
        r = run([str(REPO/'target/debug/w2l.exe'), str(pe), str(rust)], out/(name+'-conversion'), timeout=60)
        row['conversion'] = dict(exit=r['exit'], stderr=bytes.fromhex(r['stderr_hex']).decode(errors='replace'))
        assert sha(pe) == row['pe_sha256']
        if r['exit'] == 0:
            row['conversion']['rust_sha256'] = sha(rust)
        else:
            assert r['exit'] == 1 and rust.read_text() == 'preserve'
        save(out/'report.json', report)
    assert all(p['conversion']['exit'] == 1 for p in report['programs']), 'Heap execution still requires ownership/admission review'
    print('32 Windows success observations + 4 real I/O failures; both untouched conversion outcomes retained')

if __name__ == '__main__':
    main()
