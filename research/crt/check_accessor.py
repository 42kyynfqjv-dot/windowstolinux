"""Observational error-state evidence. No accessor proof/capability issuer."""
import argparse
import hashlib
import json
import os
import platform
import subprocess
import time
from pathlib import Path

from check_commode import bind

SOURCE = Path(__file__).resolve().parent
# Frozen before the first run. Hypotheses, not guaranteed postconditions.
EXPECTED = [[0, 0, 0], [33, 87, 0x20001234]]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse(stdout):
    rows = [list(map(int, line.split())) for line in stdout.splitlines()]
    if len(rows) != 2 or any(len(row) != 6 for row in rows):
        raise ValueError('two complete observations required')
    for index, row in enumerate(rows):
        i, pointer, errno, doserrno, last_error, base = row
        if (i != index or not 0 < base <= pointer <= 0xfffffffc
                or pointer % 4 or not -(2**31) <= errno < 2**31
                or not 0 <= doserrno < 2**32 or not 0 <= last_error < 2**32):
            raise ValueError('observation width/order/range')
    return rows


def assess(rows):
    # Passing samples never turn the documented no-go into an effect proof.
    return dict(error_hypotheses_match=[r[2:5] == e for r, e in zip(rows, EXPECTED)],
                same_pointer=rows[0][1] == rows[1][1],
                accessor_effects_closed=False, emission_allowed=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('evidence', nargs='?', type=Path,
                    default=Path(os.environ.get('RUNNER_TEMP', '/tmp')) / 'w2l-compiler-measurement')
    ap.add_argument('--compare', action='store_true')
    args = ap.parse_args()
    root = args.evidence.resolve()
    binding = bind(root)
    sources = {n: sha(SOURCE / n) for n in ['accessor_probe.c', 'check_accessor.py']}
    report = root / 'crt-accessor.json'
    probe = root / 'crt_accessor_probe.exe'
    if not args.compare:
        assert os.name == 'nt'
        command = ['cl', '/nologo', '/W4', '/WX', '/O2', '/MD',
                   str(SOURCE / 'accessor_probe.c'), f'/Fe{probe}']
        build = subprocess.run(command, cwd=root, capture_output=True, timeout=60)
        (root / 'crt-accessor-build.txt').write_bytes(build.stdout + build.stderr)
        assert build.returncode == 0, (build.stdout, build.stderr)
        observations = []
        for trial in range(2):
            started = time.monotonic()
            diagnostic = dict(command=[str(probe)], cwd=str(root), trial=trial,
                              platform=platform.platform(), python=platform.python_version(),
                              probe_sha256=sha(probe), original_sha256=binding['pe_sha256'])
            diagnostic_path = root / f'crt-accessor-{trial}-launch.json'
            diagnostic_path.write_text(json.dumps(diagnostic, indent=2) + '\n')
            try:
                run = subprocess.run([str(probe)], cwd=root, capture_output=True, timeout=15)
            except subprocess.TimeoutExpired as exc:
                # subprocess.run kills/waits for its owned child; no automatic retry.
                diagnostic.update(timeout=True, elapsed=time.monotonic()-started,
                                  stdout_hex=(exc.stdout or b'').hex(), stderr_hex=(exc.stderr or b'').hex())
                diagnostic_path.write_text(json.dumps(diagnostic, indent=2) + '\n')
                raise
            diagnostic.update(timeout=False, elapsed=time.monotonic()-started, exit=run.returncode,
                              stdout_hex=run.stdout.hex(), stderr_hex=run.stderr.hex())
            diagnostic_path.write_text(json.dumps(diagnostic, indent=2) + '\n')
            assert run.returncode == 0, diagnostic
            rows = parse(run.stdout)
            tag, name = run.stderr.decode().strip().split('\t')
            owner = Path(name)
            assert tag == 'OWNER' and owner.name.lower() == 'ucrtbase.dll'
            env = dict(os.environ, ACCESSOR_OWNER=str(owner))
            version = subprocess.run(['powershell', '-NoProfile', '-Command',
                '(Get-Item -LiteralPath $env:ACCESSOR_OWNER).VersionInfo.FileVersion'],
                env=env, capture_output=True, timeout=30)
            assert version.returncode == 0 and version.stdout.strip() and not version.stderr
            observations.append(dict(trial=trial, rows=rows, assessment=assess(rows),
                stdout_hex=run.stdout.hex(), stderr_hex=run.stderr.hex(), exit=run.returncode,
                owner_path=str(owner), owner_sha256=sha(owner),
                owner_version=version.stdout.decode().strip(), probe_sha256=sha(probe)))
        report.write_text(json.dumps(dict(binding=binding, sources=sources, command=command,
            platform=platform.platform(), expected=EXPECTED, observations=observations,
            decision='no-go', accessor_effects_closed=False, emission_allowed=False), indent=2) + '\n')
    out = json.loads(report.read_text())
    assert out['binding'] == binding and out['sources'] == sources and out['expected'] == EXPECTED
    assert out['decision'] == 'no-go' and out['accessor_effects_closed'] is False and out['emission_allowed'] is False
    assert [o['trial'] for o in out['observations']] == [0, 1]
    for o in out['observations']:
        rows = parse(bytes.fromhex(o['stdout_hex']))
        assert rows == o['rows'] and o['assessment'] == assess(rows)
        assert o['exit'] == 0 and o['probe_sha256'] == sha(probe)
        assert len(o['owner_sha256']) == 64 and o['owner_version']
        assert bytes.fromhex(o['stderr_hex']).decode().strip() == 'OWNER\t' + o['owner_path']
    print('ACCESSOR: two separate processes/four observations; no-go remains; hypotheses:',
          [o['assessment']['error_hypotheses_match'] for o in out['observations']])


if __name__ == '__main__':
    main()
