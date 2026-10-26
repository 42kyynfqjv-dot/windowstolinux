"""Independently convert the exact authored Windows compiler artifacts on Linux."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

root=Path(sys.argv[1]).resolve()
report_name=sys.argv[2] if len(sys.argv)>2 else 'report.json'
reports=json.loads((root/report_name).read_text())
structural=report_name=='structures-report.json'
cases=json.loads(Path('compiler/structures/cases.json' if structural else 'compiler/variations/cases.json').read_text())
if structural:
    assert {r['kind'] for r in reports}=={c['kind'] for c in cases} and len(reports)==3
expected={c['kind']:c for c in cases}
if report_name=='diversity-report.json':
    assert {r['kind'] for r in reports}==set(expected) and len(reports)==4
    assert all(r['conversion_accepted'] for r in reports), 'SUB-520 requires all four frozen variants'
converter=Path('target/debug/w2l').resolve()
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
for report in reports:
    name=report['kind']
    if name=='crt':
        continue
    source=report.get('source','compiler/program.c')
    contract=expected[name] if name in expected else dict(stdout_hex='48656c6c6f',stderr_hex='',exit=0)
    assert (report['stdout_hex'],report['stderr_hex'],report['exit'])==(contract['stdout_hex'],contract['stderr_hex'],contract['exit'])
    pe=root/(name+'.exe')
    assert digest(pe)==report['sha256'], 'original PE hash mismatch'
    assert digest(Path(source))==report['source_sha256'], 'authored source hash mismatch'
    with tempfile.TemporaryDirectory() as temporary:
        directory=Path(temporary);rust=directory/'native.rs';again=directory/'again.rs'
        for output in (rust,again):
            output.write_bytes(b'preserve rejected output')
            p=subprocess.run([str(converter),str(pe),str(output)],capture_output=True,timeout=15)
            if report['conversion_accepted']:
                assert p.returncode==0,p.stderr
                assert digest(root/(name+'.rs'))==report['rust_sha256']
                assert digest(output)==report['rust_sha256'], 'Windows/Linux emission differs'
            else:
                assert p.returncode==1 and output.read_bytes()==b'preserve rejected output'
                assert p.stderr.decode().strip()==report['converter_stderr'].strip(), 'rejection differs across hosts'
        assert digest(pe)==report['sha256'], 'conversion changed PE bytes'
        if not report['conversion_accepted']:
            print('SAME_PE_REJECTED',name,report['sha256'],report['converter_stderr'].strip())
            continue
        native=directory/'native'
        subprocess.run(['rustc','-D','warnings',str(rust),'-o',str(native)],check=True,capture_output=True,timeout=60)
        with (directory/'stdout').open('wb') as out,(directory/'stderr').open('wb') as err:
            p=subprocess.run([str(native)],stdout=out,stderr=err,timeout=15)
        observation=((directory/'stdout').read_bytes().hex(),(directory/'stderr').read_bytes().hex(),p.returncode)
        assert observation==(contract['stdout_hex'],contract['stderr_hex'],contract['exit']),observation
        print('SAME_PE_INDEPENDENT_LINUX_CONVERSION',name,report['sha256'],report['rust_sha256'],observation)

if structural:
    assert {r['kind'] for r in reports if r['conversion_accepted']} == {'variation_shared'}, 'SUB-522 requires shared acceptance, nested/conditional rejection'
