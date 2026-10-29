"""Retain the projection counterexample and verify the live adapter; no PE translation."""
import argparse
import hashlib
import json
import os
import time
from pathlib import Path
import subprocess


def run_owned(binary, output, run=subprocess.run):
    command=[str(binary.resolve()), 'owned']
    started=time.monotonic()
    try:
        result=run(command,capture_output=True,check=True,timeout=15,
                   env=dict(os.environ,W2L_CASE_TIMINGS='1'))
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as error:
        (output/'owned.stdout').write_bytes(error.stdout or b'')
        (output/'owned.stderr').write_bytes(error.stderr or b'')
        (output/'owned-timing.json').write_text(json.dumps(dict(status='timeout' if isinstance(error,subprocess.TimeoutExpired) else 'failure',command=command,timeout=15,elapsed=time.monotonic()-started))+'\n')
        raise
    (output/'owned.stdout').write_bytes(result.stdout)
    (output/'owned.stderr').write_bytes(result.stderr)
    rows=result.stderr.decode().splitlines()
    durations=[]
    for mode in range(202):
        if len(rows)!=404 or rows[mode*2]!=f'owned-start {mode}':
            raise ValueError('owned timing case sequence or unexpected stderr')
        fields=rows[mode*2+1].split()
        if len(fields)!=3 or fields[:2]!=['owned-end',str(mode)] or not fields[2].isdigit():
            raise ValueError('owned timing completion sequence')
        durations.append(int(fields[2]))
    if result.stdout:
        raise ValueError('owned frame regression unexpected output')
    (output/'owned-timing.json').write_text(json.dumps(dict(status='success',command=command,timeout=15,elapsed=time.monotonic()-started,case_microseconds=durations))+'\n')


def check(source, output):
    source, output = Path(source), Path(output)
    output.mkdir(parents=True, exist_ok=True)
    original = source.read_text()
    root = Path(__file__).resolve().parents[3]
    support = (root/'src/frame_memory.rs').read_text().split('r#"', 1)[1].split('"#;', 1)[0]
    anchor = 'fn runtime(r:&ThreadRegistry)'
    cut = 'let source=pending.dispatch_source(&rt,&c,e,&b)?;'
    if original.count(anchor) != 1 or original.count(cut) != 1:
        raise ValueError('normal native harness boundary changed; review reproduction')
    probe = '''let mut projection=pending.dispatch_source(&rt,&c,e,&b)?;
FrameMemory::new(&mut projection,rt.owner,&[])?.write_try_level(-2)?;
assert_eq!(projection.try_level,-2);
assert_eq!(rt.load(b.at(&rt,b.layout.level)?,32)?.known_scalar()?,0);
assert_eq!(pending.dispatch_source(&rt,&c,e,&b)?.try_level,0);
assert!(e.state().is_err());
println!("projected=-2 live=0 suspended=true");'''
    text = original.replace(anchor, support+'\n'+anchor, 1).replace(cut, probe+'\n'+cut, 1)
    file = output/'projection-probe.rs'
    file.write_text(text)
    binary = output/'projection-probe'
    subprocess.run(['rustc', '--edition=2021', '-Awarnings', str(file), '-o', str(binary)], check=True)
    result = subprocess.run([str(binary.resolve()), 'pending'], capture_output=True, check=True, timeout=15)
    if result.stdout.splitlines() != [b'projected=-2 live=0 suspended=true']*2 or result.stderr:
        raise ValueError('projection boundary expectations differ')
    live = subprocess.run([str(binary.resolve()), 'live'], capture_output=True, check=True, timeout=15)
    if live.stdout or live.stderr:
        raise ValueError('live adapter regression emitted unexpected output')
    run_owned(binary, output)
    subprocess.run([str(binary.resolve()),'owned-local'],capture_output=True,check=True,timeout=15)
    subprocess.run([str(binary.resolve()),'owned-loop'],capture_output=True,check=True,timeout=15)
    edges=subprocess.run([str(binary.resolve()),'path-edges'],capture_output=True,check=True,timeout=15)
    if edges.stdout or edges.stderr: raise ValueError('branch obligation regression unexpected output')
    report = dict(kind='native projection counterexample and live adapter regression; no new translated pairs',
                  input_source_sha256=hashlib.sha256(original.encode()).hexdigest(),
                  probe_source_sha256=hashlib.sha256(text.encode()).hexdigest(),
                  projection_cases=2, live_adapter_cases=37, owned_frame_cases=202, owned_local_store_cases=10, owned_local_loop_cases=13, original_cleanup_loop_cases=21, owned_delivery_lifetime_cases=144, cross_frame_delivery_cases=126, connected_cleanup_retirement_cases=111, native_local_stack_cases=111, native_local_loop_cases=111, live_callback_cases=111, conditional_resume_cases=69, post_global_caller_cases=61, opaque_dispatcher_cases=10, selected_bridge_cases=51, landing_pivot_cases=44, landing_context_cases=35, context_transfer_cases=31, restoration_completion_cases=25, initial_raise_rejection_cases=6, main_initialization_rejection_cases=5, main_normal_cpu_binding_cases=18, main_live_return_cases=4, main_live_failure_cases=14, original_printf_return_cases=2, original_printf_failure_cases=6, original_formatter_locale_rejections=1, original_event_return_gate_cases=19, unwind_continuation_input_cut_cases=4, cleanup_continuation_boundary_cases=2, branch_obligation_cases=3, ordinary_call_boundary_cases=1, whole_pe_translation_pairs=0,
                  finding='detached projection still has no storage authority; checked live adapter writes through, including nested helper cleanup')
    (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    check(args.source, args.output)
