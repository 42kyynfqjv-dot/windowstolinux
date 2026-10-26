"""Check design-only intake against untouched held-out Windows artifacts.

Expected roles/directories/relocation sites are literal observations of independently
recorded dumpbin listings, not values obtained from the prototype under test.
The production inspector is invoked here; check_native.py separately enforces conversion rejection.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from permissioned_intake import Image, Rejected

parser = argparse.ArgumentParser()
parser.add_argument('evidence', type=Path)
parser.add_argument('--compare', action='store_true')
args = parser.parse_args()
root = args.evidence
cases = json.loads(Path('compiler/heldout/cases.json').read_text())
reports = sum([json.loads((root / ('heldout-' + arch + '.json')).read_text())
               for arch in ('x86', 'x64')], [])
assert len(reports) == 8 and {r['kind'] for r in reports} == {c['kind'] for c in cases}
by_name = {r['kind']: r for r in reports}
expected_sites = {'held_loop': [(0x1006, 0x3000), (0x1015, 0x3000)],
                  'held_array': [(0x1002, 0x3004), (0x1007, 0x3008), (0x100e, 0x3000)]}
rows = []
production_rows = []
converter = Path("target/debug/w2l").resolve()
for case in cases:
    name = case['kind']
    r = by_name[name]
    assert all(r[k] == v for k, v in case.items())
    assert r['freeze_commit'] == 'cf042295303dccedb8506564f1e466ef9d353acd'
    assert hashlib.sha256(Path(case['source']).read_bytes()).hexdigest() == r['source_sha256']
    original = (root / (name + '.exe')).read_bytes()
    digest = hashlib.sha256(original).hexdigest()
    assert digest == r['sha256'] and not r['conversion_accepted']
    baseline = json.loads((root / (name + '-baseline.json')).read_text())
    assert baseline == {k: case[k] for k in ('stdout_hex', 'stderr_hex', 'exit', 'files')}
    if name == 'held_pe32plus':
        try:
            Image(original)
        except Rejected as failure:
            assert str(failure) == 'architecture: x86 PE32 required'
            result = {'sha256': digest, 'stage': 'architecture-rejected',
                      'diagnostic': str(failure), 'emission_allowed': False}
        else:
            raise AssertionError('PE32+ escaped architecture gate')
    else:
        p = Image(original)
        result = p.report()
        assert result == Image(original).report()
        assert result['emission_allowed'] is False
        assert result['base_evidence'] == 'preferred-header-only'
        if name in ('held_buffer', 'held_structure'):
            assert [s.role for s in p.sections] == ['code', 'immutable']
            assert result['directories'] == [6] and p.metadata_closed and not p.pointers
            assert result['blockers'] == ['instruction-ABI-and-provenance-proof-not-run']
        else:
            assert [s.role for s in p.sections] == ['code', 'immutable', 'writable', 'discardable-metadata']
            assert 'writable-memory-unimplemented' in p.blockers
            if name in expected_sites:
                assert result['directories'] == [5, 6] and p.metadata_closed
                assert [(v['site'], v['rva']) for v in p.pointers] == expected_sites[name]
                assert all(v['role'] == 'writable' and not v['bound'] for v in p.pointers)
                assert result['blockers'] == ['writable-memory-unimplemented',
                                             'instruction-ABI-and-provenance-proof-not-run']
            else:
                assert result['directories'] == [1, 5, 6, 10, 12]
                assert not p.metadata_closed and not p.pointers
                assert result['blockers'] == ['unsupported-directory-10', 'import-closure-unvalidated',
                                             'writable-memory-unimplemented',
                                             'relocation-and-instruction-proof-not-run']
    assert hashlib.sha256((root / (name + '.exe')).read_bytes()).hexdigest() == digest
    inspected = subprocess.run([str(converter), '--inspect-image', str(root / (name + '.exe'))], capture_output=True, timeout=15)
    repeated = subprocess.run([str(converter), '--inspect-image', str(root / (name + '.exe'))], capture_output=True, timeout=15)
    assert (inspected.returncode, inspected.stdout, inspected.stderr) == (repeated.returncode, repeated.stdout, repeated.stderr)
    assert hashlib.sha256((root / (name + '.exe')).read_bytes()).hexdigest() == digest
    if name == 'held_pe32plus':
        assert inspected.returncode == 1 and not inspected.stdout
        assert inspected.stderr.decode().strip() == 'w2l: architecture: x86 PE32 required'
        actual = {'stage': 'architecture-rejected', 'emission_allowed': False}
    else:
        assert inspected.returncode == 0 and not inspected.stderr
        actual = json.loads(inspected.stdout)
        normalized = dict(result)
        normalized.pop('sha256')
        normalized['relocation_candidates'] = [{k:v for k,v in p.items() if k != 'image'} for p in result['relocation_candidates']]
        assert actual == normalized, (name, actual, normalized)
    production_rows.append({'kind': name, 'sha256': digest, 'inspection': actual})
    print('PRODUCTION_INSPECTION_ONLY', name, digest, actual['stage'], 'emission=false')
    rows.append({'kind': name, 'baseline': baseline, 'production_diagnostic': r['converter_stderr'],
                 'prototype': result})
    print('INTAKE_DESIGN_ONLY', name, digest, result['stage'], 'emission=false')
path = root / 'permissioned-intake-report.json'
if args.compare:
    assert json.loads(path.read_text()) == rows, 'Windows/Linux prototype report mismatch'
else:
    path.write_text(json.dumps(rows, indent=2) + '\n')

production_path = root / 'production-inspection-report.json'
if args.compare:
    assert json.loads(production_path.read_text()) == production_rows
else:
    production_path.write_text(json.dumps(production_rows, indent=2)+'\n')
