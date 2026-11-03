"""Compare native component operations with independently observed Windows calls."""
from pathlib import Path
import hashlib,json,os,subprocess,sys
from sync_conformance import validate,projection
observed=Path(sys.argv[1]);out=Path(sys.argv[2]).resolve();out.mkdir(parents=True,exist_ok=False)
r=json.loads((observed/'report.json').read_text())
if r['windows_version'] != '10.0.20348':raise ValueError('unmeasured Windows host version')
if r['kind']!='authored Windows synchronization observations; no translations':raise ValueError('Windows evidence required')
frozen=json.loads(Path(__file__).with_name('sync-frozen.json').read_text())
if r['source_sha256']!=frozen['source_sha256'] or [x['spin'] for x in r['rows']]!=frozen['spins']:raise ValueError('source/scenario provenance')
if hashlib.sha256((observed/'sync.exe').read_bytes()).hexdigest()!=r['pe_sha256']:raise ValueError('observer PE changed')
try:
    p=subprocess.run(['cargo','test','--locked','--example','crt_stream','crt_provider_tests::native_sync_conformance_spins','--','--exact'],env=dict(os.environ,W2L_SYNC_OUTPUT=str(out)),capture_output=True,timeout=180)
except subprocess.TimeoutExpired as e:
    (out/'cargo.stdout').write_bytes(e.stdout or b'');(out/'cargo.stderr').write_bytes(e.stderr or b'');raise
(out/'cargo.stdout').write_bytes(p.stdout);(out/'cargo.stderr').write_bytes(p.stderr)
# Fully qualified test name is required: --exact cannot silently select zero tests.
if p.returncode or b'1 passed' not in p.stdout:raise ValueError('native conformance test did not pass')
for row in r['rows']:
    actual=json.loads((out/f"native-{row['spin']}.json").read_text())
    if validate(actual)!=validate(row):raise ValueError('Windows/native operations differ')
result=dict(kind='Windows versus Rust component operations; zero PE translations',component_pairs=len(r['rows']),windows_source_sha256=r['source_sha256'],windows_pe_sha256=r['pe_sha256'],native_runtime_sha256=hashlib.sha256(Path('src/crt_stream_runtime.rs').read_bytes()).hexdigest())
(out/'report.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
