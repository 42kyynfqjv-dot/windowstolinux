"""Bounded launch evidence. No retries; only an allowlist of nonsecret environment."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import time


def capture_process_state(pid, evidence):
    """Read only the owned child's state after failure, before termination."""
    if os.name == 'nt':
        script = (
            "$p=Get-Process -Id " + str(int(pid)) + " -ErrorAction Stop;"
            "$threads=@($p.Threads | ForEach-Object {"
            "$reason=$null;try{$reason=$_.WaitReason.ToString()}catch{};"
            "[pscustomobject]@{id=$_.Id;state=$_.ThreadState.ToString();"
            "wait_reason=$reason;start_address=$_.StartAddress.ToInt64()}});"
            "[pscustomobject]@{id=$p.Id;name=$p.ProcessName;handles=$p.HandleCount;"
            "cpu_seconds=$p.TotalProcessorTime.TotalSeconds;threads=$threads} | ConvertTo-Json -Depth 4"
        )
        command = ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script]
    else:
        command = ['ps', '-p', str(int(pid)), '-o', 'pid,ppid,stat,etime,nlwp']
    started = time.perf_counter()
    try:
        result = subprocess.run(command, capture_output=True, timeout=3)
        (evidence / 'process-state.stdout').write_bytes(result.stdout)
        (evidence / 'process-state.stderr').write_bytes(result.stderr)
        return dict(exit=result.returncode, seconds=time.perf_counter()-started)
    except Exception as error:
        return dict(error=type(error).__name__ + ': ' + str(error),
                    seconds=time.perf_counter()-started)


def execute(command, stdout, stderr, evidence, identity, expected, timeout=15):
    evidence = Path(evidence)
    evidence.mkdir(parents=True, exist_ok=True)
    record = dict(identity, command=list(command), cwd=str(Path.cwd()),
                  os=platform.platform(), python=platform.python_version(),
                  environment={k: os.environ[k] for k in ('RUNNER_OS', 'RUNNER_ARCH', 'ImageOS', 'ImageVersion') if k in os.environ},
                  expected=expected, timeout_seconds=timeout, timeout=False)
    image = Path(command[0])
    shutil.copyfile(image, evidence / 'program.bin')
    record['executed_sha256'] = hashlib.sha256(image.read_bytes()).hexdigest()
    def save():
        (evidence / 'launch.json').write_text(json.dumps(record, indent=2)+'\n')
    start = time.perf_counter()
    save()  # Persist before spawn in case process creation itself stalls.
    process = None
    try:
        with Path(stdout).open('wb') as out, Path(stderr).open('wb') as err:
            process = subprocess.Popen(command, stdout=out, stderr=err)
            record.update(pid=process.pid, spawn_seconds=time.perf_counter()-start, stage='waiting')
            save()
            wait = time.perf_counter()
            try:
                record['exit'] = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                record.update(timeout=True, poll_at_timeout=process.poll(), wait_seconds=time.perf_counter()-wait)
                record['timeout_wait_seconds'] = record['wait_seconds']
                save()  # Retain pre-kill state even if diagnostics/termination fail.
                record['process_state_capture'] = capture_process_state(process.pid, evidence)
                save()
                process.kill()
                record['exit_after_kill'] = process.wait(timeout=5)
                raise
            finally:
                record['wait_seconds'] = time.perf_counter()-wait
    except BaseException as failure:
        record['failure'] = type(failure).__name__ + ': ' + str(failure)
        raise
    finally:
        record['elapsed_seconds'] = time.perf_counter()-start
        record['stage'] = 'finished' if 'failure' not in record else 'failed'
        if process is not None:
            record['final_poll'] = process.poll()
        for name, source in [('stdout', stdout), ('stderr', stderr)]:
            if Path(source).exists():
                shutil.copyfile(source, evidence / name)
                record[name+'_hex'] = Path(source).read_bytes().hex()
        save()
    return process
