"""SUB-543 isolated effect/CPU comparison; never an ordinary CRT translation claim."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

REPO=Path(__file__).resolve().parents[2]
SOURCE=REPO/'research/crt'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(command):
    p=subprocess.run([str(x) for x in command],capture_output=True,timeout=60)
    assert p.returncode==0 and not p.stderr,(command,p.returncode,p.stdout,p.stderr)
    return p.stdout

def main():
    ap=argparse.ArgumentParser();ap.add_argument('evidence',nargs='?',type=Path,default=Path(os.environ.get('RUNNER_TEMP','/tmp'))/'w2l-compiler-measurement');ap.add_argument('--windows-probe',action='store_true');ap.add_argument('--compare',action='store_true');a=ap.parse_args();root=a.evidence.resolve()
    pe=root/'held_crt.exe';record=next(r for r in json.loads((root/'heldout-x86.json').read_text()) if r['kind']=='held_crt')
    assert sha(pe)==record['sha256'] and not record['conversion_accepted']
    subprocess.run(['cargo','build','--locked','--example','crt_sentinel'],cwd=REPO,check=True)
    binary=REPO/'target/debug/examples'/('crt_sentinel.exe' if os.name=='nt' else 'crt_sentinel')
    spec=json.loads((SOURCE/'sentinel-vectors.json').read_text())['positive']
    base=json.loads(run([binary,pe]));assert not base['synthetic_vector'] and not base['emission_allowed'] and not base['prior_effects_closed']
    results=[]
    for v in spec:
        command=[binary,pe,'--vector',v['flag'],v['mode'],'?' if v['policy'] is None else v['policy'],v['eax'],v['known'],v['before']]
        raw=run(command);assert raw==run(command);r=json.loads(raw)
        assert (r['tables_after'],r['eax'],r['eax_known'],r['defined_flags'],r['af'],r['peak_stack_bytes_below_entry'])==(v['after'],v['result_eax'],v['result_known'],v['flags'],v['af'],v['peak']),v
        assert r['flag_after']==(v['flag'] or 1) and r['stack_delta_from_helper_entry']==4
        expected_writes=[] if v['flag'] else [[12460,'ffffffff'],[12464,'ffffffff'],[12468,'ffffffff'],[12472,'ffffffff'],[12476,'ffffffff'],[12480,'ffffffff'],[12457,'01']]
        assert r['writes']==expected_writes and not r['complete_startup_proof'] and not r['emission_allowed']
        assert r['preserved_registers']==['ebx','ecx','edx','esi','edi','ebp']
        results.append(dict(name=v['name'],result=r))
    # CLI boundary rejects fractions, oversized words/flags and invalid masks before effects.
    negatives=[]
    for index,bad in [(0,'256'),(0,'0.5'),(1,'1.5'),(1,'4294967296'),(2,'0'),(2,'?'),(2,'2'),(2,'0.5'),(3,'-1'),(3,'4294967296'),(3,'1.0'),(4,'0.5'),(4,'0'),(5,'ff')]:
        values=['0','1','1','1','4294967295','00'*24];values[index]=bad
        p=subprocess.run([str(binary),str(pe),'--vector',*values],capture_output=True,timeout=60)
        assert p.returncode==1 and not p.stdout and p.stderr.startswith(b'sentinel rejected:'),(index,bad,p)
        negatives.append(dict(field=index,value=bad,stderr=p.stderr.decode().strip()))
    out=dict(pe_sha256=sha(pe),rust_source_sha256=sha(REPO/'examples/crt_sentinel.rs'),spec_sha256=sha(SOURCE/'sentinel-vectors.json'),checker_sha256=sha(Path(__file__)),original_snapshot=base,vectors=results,negative_cli=negatives,complete_startup_proof=False,emission_allowed=False)
    report=root/'crt-sentinel.json'
    if a.compare:assert json.loads(report.read_text())==out
    else:report.write_text(json.dumps(out,indent=2)+'\n')
    cpu_path=root/'crt-sentinel-cpu.json';probe=root/'crt_sentinel_probe.exe'
    if a.windows_probe:
        assert os.name=='nt'
        p=subprocess.run(['cl','/nologo','/W4','/WX','/O2',str(SOURCE/'sentinel_probe.c'),f'/Fe{probe}'],cwd=root,capture_output=True,timeout=60)
        (root/'crt-sentinel-probe-build.txt').write_bytes(p.stdout+p.stderr);assert p.returncode==0,(p.stdout,p.stderr)
        observations=[]
        for v in spec:
            # Unknown upper bits concretized independently twice; only known bits compared.
            for incoming in sorted({v['eax'],v['eax'] | (0xffffffff ^ v['known'])}):
                command=[probe,v['flag'],v['mode'],v['policy'] if v['policy'] is not None else 99,incoming,v['before']]
                raw=run(command);r=json.loads(raw)
                assert r['tables_after']==v['after'] and r['flag_after']==(v['flag'] or 1)
                assert r['eax'] & v['result_known']==v['result_eax'] and r['defined_flags']==v['flags'] and r['preserved_context']
                if v['af'] is not None:assert r['af_bit']==int(v['af'])
                observations.append(dict(name=v['name'],incoming=incoming,raw_stdout_hex=raw.hex(),stderr_hex='',exit=0,result=r))
        cpu_path.write_text(json.dumps(dict(source_sha256=sha(SOURCE/'sentinel_probe.c'),probe_sha256=sha(probe),spec_sha256=out['spec_sha256'],observations=observations,separate_authored_cpu_probe=True,original_program_translation=False),indent=2)+'\n')
    if a.compare:
        cpu=json.loads(cpu_path.read_text());assert cpu['source_sha256']==sha(SOURCE/'sentinel_probe.c') and cpu['probe_sha256']==sha(probe) and cpu['spec_sha256']==out['spec_sha256']
        expected=[(v,incoming) for v in spec for incoming in sorted({v['eax'],v['eax'] | (0xffffffff ^ v['known'])})]
        assert len(cpu['observations'])==len(expected)==11
        for o,(v,incoming) in zip(cpu['observations'],expected):
            r=o['result'];assert o['name']==v['name'] and o['incoming']==incoming and o['exit']==0 and o['stderr_hex']==''
            assert json.loads(bytes.fromhex(o['raw_stdout_hex']))==r
            assert r['tables_after']==v['after'] and r['flag_after']==(v['flag'] or 1) and r['eax'] & v['result_known']==v['result_eax'] and r['defined_flags']==v['flags'] and r['preserved_context']
            if v['af'] is not None:assert r['af_bit']==int(v['af'])
    assert sha(pe)==record['sha256']
    print('SENTINEL: eight isolated vectors, fourteen CLI rejections; no ordinary CRT translation')
if __name__=='__main__':main()
