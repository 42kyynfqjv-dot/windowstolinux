"""Independent same-PE cross-host checks for accepted OR rejected held-out input."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
root=Path(sys.argv[1]).resolve()
cases=json.loads(Path('compiler/heldout/cases.json').read_text())
reports=sum([json.loads((root/('heldout-'+arch+'.json')).read_text()) for arch in ('x86','x64')],[])
assert len(reports)==8 and {r['kind'] for r in reports}=={c['kind'] for c in cases}
converter=Path('target/debug/w2l').resolve()
expected={c['kind']:c for c in cases}
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
for report in reports:
    name=report['kind'];case=expected[name]
    for key,value in case.items():assert report[key]==value
    assert sha(Path(case['source']))==report['source_sha256']
    pe=root/(name+'.exe');assert sha(pe)==report['sha256']
    with tempfile.TemporaryDirectory() as temporary:
        work=Path(temporary);rust=work/'native.rs'
        for _ in range(2):
            rust.write_bytes(b'preserve')
            p=subprocess.run([str(converter),str(pe),str(rust)],capture_output=True,timeout=15)
            if not report['conversion_accepted']:
                assert p.returncode==1 and rust.read_bytes()==b'preserve'
                assert p.stderr.decode().strip()==report['converter_stderr'].strip()
            else:
                assert p.returncode==0 and sha(rust)==report['rust_sha256']==sha(root/(name+'.rs'))
        assert sha(pe)==report['sha256']
        if not report['conversion_accepted']:
            print('HELD_SAME_PE_REJECTED',name,report['sha256'],report['converter_stderr'].strip());continue
        native=work/'native'
        subprocess.run(['rustc','-D','warnings',str(rust),'-o',str(native)],check=True,capture_output=True,timeout=60)
        with (work/'stdout').open('wb') as out,(work/'stderr').open('wb') as err:
            p=subprocess.run([str(native)]+case['args'],cwd=work,stdout=out,stderr=err,timeout=15)
        assert ((work/'stdout').read_bytes().hex(),(work/'stderr').read_bytes().hex(),p.returncode)==(case['stdout_hex'],case['stderr_hex'],case['exit'])
        assert {n:(work/n).read_bytes().hex() for n in case['files']}==case['files']
        print('HELD_SAME_PE_NATIVE',name,report['sha256'],report['rust_sha256'])
