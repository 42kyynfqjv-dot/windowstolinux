"""Separate Linux component evidence, never a converter success."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('evidence',type=Path);a=p.parse_args()
repo=Path(__file__).resolve().parents[2];source=repo/'examples/bounded_input.rs'
exe=repo/'target/debug/examples/bounded_input'
prior=json.loads((a.evidence/'input-contract.json').read_text(encoding='utf-8'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(a.evidence/'input.exe')==prior['pe_sha256']
vectors=json.loads((repo/'research/input/vectors.json').read_text(encoding='utf-8'))
assert sha(repo/'research/input/vectors.json')==prior['sources']['vectors.json']
results=[]
for v in vectors:
    env={} if v['value'] is None else {'W2L_INPUT':v['value']}
    r=subprocess.run([str(exe)],env=env,capture_output=True,timeout=10)
    actual=dict(name=v['name'],exit=r.returncode,stdout_hex=r.stdout.hex(),stderr_hex=r.stderr.hex())
    assert actual==dict(name=v['name'],exit=v['exit'],stdout_hex='',stderr_hex=''),actual
    results.append(actual)
assert results==prior['observations']
# Host-domain negatives are separate from the frozen Windows observations.
for env in [{b'W2L_INPUT':b'\xff'}, {b'w2l_input':b'7'}, {b'W2L_INPUT':b'7',b'w2l_input':b'42'}, {b'OTHER':b'x'*4097}, {b'W2L_\xc4\xb1NPUT':b'7'}]:
    r=subprocess.run([os.fsencode(exe)],env=env,capture_output=True,timeout=10)
    assert (r.returncode,r.stdout,r.stderr)==(203,b'',b'')
out=dict(component_sha256=sha(source),acquisition_sha256=sha(repo/'src/linker/input/acquisition.rs'),binary_sha256=sha(exe),pe_sha256=prior['pe_sha256'],
         observations=results,linux_host_rejections=5,source='initial /proc/self/environ',
         separate_component=True,conversion_accepted=False)
(a.evidence/'input-acquisition.json').write_text(json.dumps(out,indent=2)+'\n')
print('ACQUISITION:17 inherited Windows/component matches;5 Linux host-domain rejections; no PE conversion')
