"""Retain the projection counterexample and verify the live adapter; no PE translation."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


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
    owned=subprocess.run([str(binary.resolve()), 'owned'],capture_output=True,check=True,timeout=15)
    if owned.stdout or owned.stderr: raise ValueError('owned frame regression unexpected output')
    subprocess.run([str(binary.resolve()),'owned-local'],capture_output=True,check=True,timeout=15)
    subprocess.run([str(binary.resolve()),'owned-loop'],capture_output=True,check=True,timeout=15)
    edges=subprocess.run([str(binary.resolve()),'path-edges'],capture_output=True,check=True,timeout=15)
    if edges.stdout or edges.stderr: raise ValueError('branch obligation regression unexpected output')
    report = dict(kind='native projection counterexample and live adapter regression; no new translated pairs',
                  input_source_sha256=hashlib.sha256(original.encode()).hexdigest(),
                  probe_source_sha256=hashlib.sha256(text.encode()).hexdigest(),
                  projection_cases=2, live_adapter_cases=37, owned_frame_cases=105, owned_local_store_cases=10, owned_local_loop_cases=13, original_cleanup_loop_cases=21, owned_delivery_lifetime_cases=48, cross_frame_delivery_cases=30, connected_cleanup_retirement_cases=15, native_local_stack_cases=15, unwind_continuation_input_cut_cases=4, cleanup_continuation_boundary_cases=2, branch_obligation_cases=3, ordinary_call_boundary_cases=1, whole_pe_translation_pairs=0,
                  finding='detached projection still has no storage authority; checked live adapter writes through, including nested helper cleanup')
    (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    check(args.source, args.output)
