"""Bind an unchanged authored PE and compare five preregistered operation vectors.
These are isolated CPU/Rust operations, never translated CRT program evidence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

REPO = Path(__file__).resolve().parents[2]

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def run(args, **kwargs):
    p = subprocess.run([str(a) for a in args], capture_output=True, timeout=60, **kwargs)
    if p.returncode or p.stderr:
        raise AssertionError((args, p.returncode, p.stdout, p.stderr))
    return p.stdout

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('evidence', type=Path, nargs='?', default=Path(os.environ.get('RUNNER_TEMP','/tmp'))/'w2l-compiler-measurement')
    ap.add_argument('--windows-probe', action='store_true')
    ap.add_argument('--compare', action='store_true')
    args = ap.parse_args()
    root = args.evidence.resolve()
    source = REPO / 'research/crt'
    pe = root / 'held_crt.exe'
    record = next(r for r in json.loads((root/'heldout-x86.json').read_text()) if r['kind']=='held_crt')
    assert sha(pe)==record['sha256'] and not record['conversion_accepted']
    subprocess.run(['cargo','build','--locked','--example','crt_option_state'], check=True, cwd=REPO)
    binary = REPO / 'target/debug/examples' / ('crt_option_state.exe' if os.name=='nt' else 'crt_option_state')
    bound = json.loads(run([binary,pe]))
    assert not bound['emission_allowed'] and not bound['complete_startup_proof'] and not bound['synthetic_vector']
    specification = json.loads((source/'option-state-vectors.json').read_text())
    vectors = []
    for v in specification['positive']:
        result = json.loads(run([binary, pe, '--vector', v['before']]))
        expected = dict(specification['post_callback'],after=v['after'],ecx=int.from_bytes(bytes.fromhex(v['before'])[12:16],'little'),pf=True,af=None,helper_defined_flags=v['helper_defined_flags'])
        assert all(result[k]==value for k,value in expected.items()), (v,result)
        assert result['synthetic_vector'] and not result['emission_allowed']
        assert result['preserved_registers']==['ebx','edx','esi','edi','ebp']
        assert result['stack_delta_from_callback_entry']==4 and result['peak_stack_bytes_below_entry']==8
        assert run([binary,pe,'--vector',v['before']])==run([binary,pe,'--vector',v['before']])
        vectors.append(dict(name=v['name'],expected=expected,result=result))
    out = dict(pe_sha256=sha(pe), spec_sha256=sha(source/'option-state-vectors.json'),
               model_source_sha256=sha(REPO/'examples/crt_option_state.rs'),original_snapshot=bound,
               vectors=vectors,complete_startup_proof=False,emission_allowed=False)
    path=root/'crt-option-state.json'
    if args.compare:
        assert json.loads(path.read_text())==out
    else:
        path.write_text(json.dumps(out,indent=2)+'\n')
    if args.windows_probe:
        assert os.name=='nt'
        probe=root/'crt_option_probe.exe'
        p=subprocess.run(['cl','/nologo','/W4','/WX','/O2',str(source/'option_probe.c'),f'/Fe{probe}'],cwd=root,capture_output=True,timeout=60)
        (root/'crt-option-probe-build.txt').write_bytes(p.stdout+p.stderr)
        assert p.returncode==0,(p.stdout,p.stderr)
        observations=[]
        for v in specification['positive']:
            result=json.loads(run([probe,v['before']],cwd=root))
            assert result['after']==v['after'] and result['eax']==0
            assert result['ecx']==int.from_bytes(bytes.fromhex(v['before'])[12:16],'little')
            # CF, PF, ZF, SF, OF defined by final XOR. AF deliberately excluded.
            assert result['eflags'] & 0x8c5 == 0x44
            assert result['helper_defined_flags']==v['helper_defined_flags']
            observations.append(dict(name=v['name'],result=result))
        (root/'crt-option-cpu.json').write_text(json.dumps(dict(source_sha256=sha(source/'option_probe.c'),
            probe_sha256=sha(probe),spec_sha256=out['spec_sha256'],observations=observations,
            separate_authored_cpu_probe=True,original_program_translation=False),indent=2)+'\n')
    if args.compare:
        cpu=json.loads((root/'crt-option-cpu.json').read_text())
        assert cpu['spec_sha256']==out['spec_sha256'] and cpu['source_sha256']==sha(source/'option_probe.c')
        assert cpu['probe_sha256']==sha(root/'crt_option_probe.exe')
        assert len(cpu['observations'])==len(vectors)==5
        for observed,model in zip(cpu['observations'],vectors):
            assert observed['name']==model['name']
            assert all(observed['result'][k]==model['expected'][k] for k in ('after','eax','ecx','helper_defined_flags'))
            assert observed['result']['eflags'] & 0x8c5 == 0x44
    assert sha(pe)==record['sha256']
    print('OPTION_STATE: bound unchanged PE; five independent vectors; startup incomplete; emission false')

if __name__=='__main__':
    main()
