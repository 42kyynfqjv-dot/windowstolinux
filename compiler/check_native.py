"""Verify the original authored MSVC artifact before independent Linux conversion."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(sys.argv[1]).resolve()
report = json.loads((root/'report.json').read_text())[0]
assert report['kind'] == 'freestanding' and report['conversion_accepted']

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

pe = root/'freestanding.exe'
assert digest(pe) == report['sha256'], 'original PE hash mismatch'
assert digest(Path('compiler/program.c')) == report['source_sha256'], 'authored source hash mismatch'
assert digest(root/'freestanding.rs') == report['rust_sha256'], 'Windows generated Rust hash mismatch'
converter = Path('target/debug/w2l').resolve()
with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary)
    rust = directory/'native.rs'
    again = directory/'again.rs'
    for output in (rust, again):
        subprocess.run([str(converter), str(pe), str(output)], check=True, capture_output=True, timeout=15)
        assert digest(output) == report['rust_sha256'], 'Windows/Linux emission differs'
    assert digest(pe) == report['sha256'], 'conversion changed PE bytes'
    native = directory/'native'
    subprocess.run(['rustc', '-D', 'warnings', str(rust), '-o', str(native)], check=True, capture_output=True, timeout=60)
    with (directory/'stdout').open('wb') as out, (directory/'stderr').open('wb') as err:
        process = subprocess.run([str(native)], stdout=out, stderr=err, timeout=15)
    observation = ((directory/'stdout').read_bytes().hex(), (directory/'stderr').read_bytes().hex(), process.returncode)
    assert observation == (report['stdout_hex'], report['stderr_hex'], report['exit']) == ('48656c6c6f', '', 0), observation
    print('SAME_PE_INDEPENDENT_LINUX_CONVERSION', report['sha256'], report['rust_sha256'], observation)
