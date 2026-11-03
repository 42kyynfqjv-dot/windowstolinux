"""Bounded launch evidence. No retries; only an allowlist of nonsecret environment."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time


def windows_owned_creation(process_handle):
    """Get identity from Popen's retained handle, never reopen an arbitrary PID."""
    import ctypes as C
    if process_handle is None:
        raise ValueError('retained owned process handle required')
    api = C.WinDLL('kernel32', use_last_error=True).GetProcessTimes
    api.restype = C.c_int32
    api.argtypes = [C.c_void_p] + [C.POINTER(C.c_uint64)] * 4
    times = [C.c_uint64() for _ in range(4)]
    if not api(int(process_handle), *(C.byref(t) for t in times)):
        raise C.WinError(C.get_last_error())
    return times[0].value


def capture_process_state(pid, evidence, process_handle=None):
    """Observe only the owned child; observer timeout cannot replace its failure."""
    started = time.perf_counter()
    try:
        if os.name == 'nt':
            creation = windows_owned_creation(process_handle)
            observer = os.path.join(os.path.dirname(__file__), 'windows_wait_observer.py')
            command = [sys.executable, observer, str(int(pid)), str(creation)]
        else:
            command = ['ps', '-p', str(int(pid)), '-o', 'pid,ppid,stat,etime,nlwp']
        result = subprocess.run(command, capture_output=True, timeout=3)
        (evidence / 'process-state.stdout').write_bytes(result.stdout)
        (evidence / 'process-state.stderr').write_bytes(result.stderr)
        return dict(exit=result.returncode, seconds=time.perf_counter()-started)
    except subprocess.TimeoutExpired as error:
        # subprocess.run kills/reaps only the observer; retain partial evidence
        # when possible. A full/unwritable disk must not escape this observer.
        result = dict(error=type(error).__name__ + ': ' + str(error),
                      seconds=time.perf_counter()-started)
        for name, data in [('stdout', error.stdout), ('stderr', error.stderr)]:
            try:
                (evidence / ('process-state.' + name)).write_bytes(data or b'')
            except Exception as write_error:
                result.setdefault('evidence_errors', []).append(
                    type(write_error).__name__ + ': ' + str(write_error))
        return result
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
    primary_failure = None
    cleanup_attempted = False

    def diagnostic_error(stage, error):
        record.setdefault('diagnostic_errors', []).append(
            dict(stage=stage, error=type(error).__name__ + ': ' + str(error)))

    def save_failure_evidence():
        try:
            save()
        except Exception as error:
            diagnostic_error('save', error)

    def cleanup_failed_child():
        nonlocal cleanup_attempted
        if process is None or cleanup_attempted:
            return
        cleanup_attempted = True
        try:
            if process.poll() is None:
                process.kill()
                record['exit_after_kill'] = process.wait(timeout=5)
            else:
                record['exit_during_diagnostics'] = process.wait(timeout=5)
        except Exception as error:
            diagnostic_error('child-cleanup', error)

    try:
        with Path(stdout).open('wb') as out, Path(stderr).open('wb') as err:
            process = subprocess.Popen(command, stdout=out, stderr=err)
            record.update(pid=process.pid, spawn_seconds=time.perf_counter()-start, stage='waiting')
            save()
            wait = time.perf_counter()
            try:
                record['exit'] = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                record['timeout'] = True
                try:
                    record.update(poll_at_timeout=process.poll(), wait_seconds=time.perf_counter()-wait)
                    record['timeout_wait_seconds'] = record['wait_seconds']
                    save_failure_evidence()
                    try:
                        record['process_state_capture'] = capture_process_state(process.pid, evidence, getattr(process, '_handle', None))
                    except Exception as error:
                        diagnostic_error('observer', error)
                    save_failure_evidence()
                except Exception as error:
                    diagnostic_error('timeout-diagnostics', error)
                finally:
                    # Observer/save failures must never leave our timed-out child alive.
                    cleanup_failed_child()
                raise  # Preserve the original child TimeoutExpired, not observer failure.
            finally:
                record['wait_seconds'] = time.perf_counter()-wait
    except BaseException as failure:
        primary_failure = failure
        record['failure'] = type(failure).__name__ + ': ' + str(failure)
        raise
    finally:
        # Also cover an evidence-write failure immediately after successful spawn.
        if primary_failure is not None:
            cleanup_failed_child()
        record['elapsed_seconds'] = time.perf_counter()-start
        record['stage'] = 'finished' if primary_failure is None else 'failed'
        try:
            if process is not None:
                record['final_poll'] = process.poll()
            for name, source in [('stdout', stdout), ('stderr', stderr)]:
                if Path(source).exists():
                    shutil.copyfile(source, evidence / name)
                    record[name+'_hex'] = Path(source).read_bytes().hex()
            save()
        except Exception as error:
            if primary_failure is None:
                raise
            diagnostic_error('final-evidence', error)
            save_failure_evidence()
    return process
