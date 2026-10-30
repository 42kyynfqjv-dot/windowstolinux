"""Validate root-authority, reserved-flag, and capture-mask regressions with compiled mutants.

Input is the generated authored Rust component harness, never a Windows binary.
The mutant must compile and fail with the precise unexpected-success assertion.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def check(source: Path, output: Path, mutation="root"):
    output.mkdir(parents=True, exist_ok=False)
    raw = source.read_bytes()
    guard = '  if state.previous!=self.root||self.root!=RegistryHead::Owned(state.selected){return Err("ordered search incoming root authority changed");}'
    text = raw.decode()
    replacement = '  // Intentionally removed root guard.'
    left = b'left: Ok(1)'
    right = b'right: Err("ordered search incoming root authority changed")'
    observed = 'Ok(1) where changed-root rejection was required'
    if mutation == 'flags':
        guard = 'rt.store(rt.offset(record,4)?,32,CrtValue::Scalar{bits:u32::from(self.noncontinuable),known:1})?;'
        replacement = 'rt.store(rt.offset(record,4)?,32,CrtValue::scalar(u32::from(self.noncontinuable)))?;'
        left = b'left: Scalar { bits: 0, known: 4294967295 }'
        right = b'right: Scalar { bits: 0, known: 1 }'
        observed = 'reserved bits became known zero instead of remaining unknown'
    if mutation == 'capture':
        guard = 'if high<=self.base{Ok(true)}else if low>self.base'
        replacement = 'if low<=self.base{Ok(true)}else if low>self.base'
        left = b'left: None'
        right = b'right: Some("captured stack comparison unknown")'
        observed = 'ambiguous upper-bound capture admitted after ignoring unknown bits'
    if text.count(guard) != 1:
        raise ValueError('mutation source binding must be unique')
    mutant = output / 'mutant.rs'
    mutant.write_text(text.replace(guard, replacement, 1))
    binary = output / 'mutant'
    built = subprocess.run(['rustc', '--edition=2021', '-Awarnings', str(mutant), '-o', str(binary)], capture_output=True, timeout=60)
    (output / 'build.stderr').write_bytes(built.stderr)
    if built.returncode:
        raise ValueError('mutation must compile before testing rejection evidence')
    run = subprocess.run([str(binary.resolve()), 'ordered-search'], capture_output=True, timeout=30)
    (output / 'stdout').write_bytes(run.stdout)
    (output / 'stderr').write_bytes(run.stderr)
    if run.returncode != 101 or left not in run.stderr or right not in run.stderr:
        raise ValueError('missing exact regression assertion; other failure cannot count')
    report = dict(kind=mutation+' proof mutation; native component only', source_sha256=hashlib.sha256(raw).hexdigest(), mutant_sha256=hashlib.sha256(mutant.read_bytes()).hexdigest(), returncode=run.returncode, observed=observed, whole_pe_pairs=0, new_windows_observations=0)
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--mutation', choices=['root', 'flags', 'capture'], default='root')
    args = parser.parse_args()
    check(args.source, args.output, args.mutation)
