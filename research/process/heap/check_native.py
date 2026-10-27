"""Native COMPONENT versus Windows effects; separately verify PE conversion rejects."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

here=Path(__file__).resolve().parent
repo=here.parents[2]
out=Path(sys.argv[1]).resolve()
report=json.loads((out/'report.json').read_text())
manifest=json.loads((here/'frozen.json').read_text())
assert report['manifest']==manifest
for name,digest in manifest['sha256'].items():
    assert hashlib.sha256((here/name).read_bytes()).hexdigest()==digest
cases=json.loads((here/'cases.json').read_text())
subprocess.run(['cargo','build','--locked','--example','heap_effects'],cwd=repo,check=True)
rows=[]
for row in report['programs']:
    name=row['name'];pe=out/(name+'.exe');rust=out/(name+'-linux.rs')
    assert hashlib.sha256(pe.read_bytes()).hexdigest()==row['pe_sha256']
    rust.write_text('preserve')
    p=subprocess.run([str(repo/'target/debug/w2l'),str(pe),str(rust)],capture_output=True,timeout=60)
    assert p.returncode==row['conversion']['exit']==1 and rust.read_text()=='preserve'
    assert p.stderr.decode()==row['conversion']['stderr']
    observations={o['name']:o for o in row['observations']}
    assert len(observations)==len(cases)
    for case in cases:
        observation=observations[case['name']]
        assert observation['executed_sha256']==row['pe_sha256'] and not observation['timeout']
        p=subprocess.run([str(repo/'target/debug/examples/heap_effects'),name],input=bytes.fromhex(case['input_hex']),capture_output=True,timeout=15)
        assert (p.returncode,p.stdout.hex(),p.stderr.hex())==(0,case['expected'][name],'')
        assert (p.returncode,p.stdout.hex(),p.stderr.hex())==(observation['exit'],observation['stdout_hex'],observation['stderr_hex'])
        rows.append(dict(program=name,case=case['name'],component_match=True))
result=dict(component_comparisons=rows,translated_pe_comparisons=0,unchanged_pe_rejections=2,
            component_source_sha256=hashlib.sha256((repo/'examples/heap_effects.rs').read_bytes()).hexdigest())
(out/'native-component.json').write_text(json.dumps(result,indent=2)+'\n')
print('32 native COMPONENT comparisons; zero heap PE translations; two unchanged rejections')
