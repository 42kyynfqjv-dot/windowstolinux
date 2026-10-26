"""Independent expected outcomes for isolated onexit probes, not translation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from onexit_inventory import inventory
from onexit_model import conversion

REPO=Path(__file__).resolve().parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(args,**kw):return subprocess.run([str(a) for a in args],capture_output=True,timeout=30,**kw)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('evidence',nargs='?',type=Path,default=Path(os.environ.get('RUNNER_TEMP','/tmp'))/'w2l-compiler-measurement');ap.add_argument('--compare',action='store_true');args=ap.parse_args()
    root=args.evidence.resolve();source=REPO/'research/crt';binding=inventory(root)
    files=['onexit_probe.c','onexit_model.py','onexit_inventory.py','check_onexit.py']
    source_hashes={n:sha(source/n) for n in files}
    expected={'tables':b'BA|C|C','process':b'YX','crt':b'YX','scalar':b'0 1\n0 1\n0 1\n4294967295 68\n4294967295 68\n4294967295 68\n'}
    # Six independent scalar expectations, including null as arithmetic only (never passed to CRT).
    cases=[(1,0),(0x80000000,0),(0xffffffff,0),(0,0),(1,1),(1,0xffffffff)]
    assert [conversion(*x) for x in cases]==[(0,1),(0,1),(0,1),(0xffffffff,68),(0xffffffff,68),(0xffffffff,68)]
    path=root/'crt-onexit-probes.json';probe=root/'crt_onexit_probe.exe'
    if args.compare:
        out=json.loads(path.read_text())
        assert out['pe_sha256']==binding['pe_sha256'] and out['sources']==source_hashes
        assert out['probe_sha256']==sha(probe)
        assert out['binding']==binding and not out['emission_allowed']
        assert list(out['observations'])==list(expected)
        for mode,output in expected.items():
            r=out['observations'][mode]
            assert bytes.fromhex(r['stdout_hex']).replace(b'\r\n',b'\n')==output and r['exit']==0
            assert r['normalized_stdout_hex']==output.hex()
            assert (not r['modules']) if mode=='scalar' else any(x['name']=='ucrtbase.dll' and x['sha256'] and x['version'] for x in r['modules'])
    else:
        assert os.name=='nt'
        p=run(['cl','/nologo','/W4','/WX','/O2','/MD',source/'onexit_probe.c',f'/Fe{probe}'],cwd=root)
        (root/'crt-onexit-probe-build.txt').write_bytes(p.stdout+p.stderr);assert p.returncode==0,(p.stdout,p.stderr)
        observations={}
        for mode,output in expected.items():
            p=run([probe,mode],cwd=root)
            assert p.returncode==0 and p.stdout.replace(b'\r\n',b'\n')==output,(mode,p.returncode,p.stdout,p.stderr)
            modules=[]
            for line in p.stderr.decode().splitlines():
                parts=line.split('\t');assert len(parts)==3 and parts[0]=='MODULE'
                mod=Path(parts[2]);env=dict(os.environ,ONEXIT_MODULE_PATH=str(mod))
                version=run(['powershell','-NoProfile','-Command','(Get-Item -LiteralPath $env:ONEXIT_MODULE_PATH).VersionInfo.FileVersion'],env=env)
                assert version.returncode==0 and not version.stderr
                modules.append(dict(name=mod.name.lower(),path=str(mod),base=int(parts[1]),sha256=sha(mod),version=version.stdout.decode().strip()))
            if mode!='scalar':assert any(x['name']=='ucrtbase.dll' for x in modules)
            observations[mode]=dict(stdout_hex=p.stdout.hex(),normalized_stdout_hex=p.stdout.replace(b'\r\n',b'\n').hex(),stderr_hex=p.stderr.hex(),exit=p.returncode,modules=modules,stderr_is_module_evidence=True)
        out=dict(pe_sha256=binding['pe_sha256'],binding=binding,sources=source_hashes,probe_sha256=sha(probe),
                 compiler_flags=['/W4','/WX','/O2','/MD'],observations=observations,original_program_translation=False,
                 observed_allocation_failures=False,complete_startup_proof=False,emission_allowed=False)
        path.write_text(json.dumps(out,indent=2)+'\n')
        (root/'crt-onexit-inventory.json').write_text(json.dumps(binding,indent=2)+'\n')
    print('ONEXIT_PROBES: three isolated lifecycle/order probes; six scalar CPU cases; startup unresolved; emission false')

if __name__=='__main__':main()
