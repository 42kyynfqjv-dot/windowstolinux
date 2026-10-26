"""Bound original callback preconditions; evidence audit only, no certificate issuer."""
import argparse,hashlib,json,os,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
PREFIX=bytes.fromhex('566a01e8680c0000e8a306000050e8930c0000e8780600008bf0e8b70c00006a018930e88803000083c40c5e84c07478')
PREDECESSORS=[(0x1033,'api-ms-win-crt-runtime-l1-1-0.dll!_set_app_type'),(0x103e,'api-ms-win-crt-stdio-l1-1-0.dll!_set_fmode')]
def sha(b):return hashlib.sha256(b).hexdigest()
def audit(b,callbacks,runtime):
    h=sha(b)
    assert callbacks['pe_sha256']==runtime['binding']['pe_sha256']==h
    assert callbacks['complete_effect_proof'] is False and callbacks['emission_allowed'] is False
    assert runtime['effect_proof'] is False and runtime['emission_allowed'] is False
    assert runtime['normalized_match'] is True and runtime['machine']==0x14c
    pe=struct.unpack_from('<I',b,60)[0];o=pe+24;t=o+struct.unpack_from('<H',b,pe+20)[0]
    sections=[struct.unpack_from('<IIII',b,t+i*40+8) for i in range(struct.unpack_from('<H',b,pe+6)[0])]
    def read(r,n):
        hits=[p+r-v for size,v,length,p in sections if v<=r and r+n<=v+min(size,length)]
        assert len(hits)==1 and hits[0]+n<=len(b);return b[hits[0]:hits[0]+n]
    assert read(0x1030,len(PREFIX))==PREFIX
    assert read(0x16e0,6)==bytes.fromhex('b800400000c3') and read(0x16c0,3)==bytes.fromhex('33c0c3')
    prior=[(c['site_rva'],c['imported']) for c in callbacks['direct_calls'] if c['site_rva']<0x104a and c['imported']]
    assert prior==PREDECESSORS
    leaf=runtime['leaf'];assert leaf and leaf['destination']=='EAX' and leaf['length']==6
    assert runtime['rva']+1 in runtime['relocation_sites']
    assert leaf['value']==runtime['base']+leaf['object_rva'] and leaf['object_rva']==0x104768
    return dict(pe_sha256=h,predecessors=[dict(site=site,imported=name,effect_closed=False) for site,name in prior],
        conditional_local_trace=dict(esi_after_zero_helper=0,pending_words_before_accessor=['fmode=0x4000','app_type=1','saved_ESI','callback_return'],pending_words_before_sentinel=['policy=1','fmode=0x4000','app_type=1','saved_ESI','callback_return'],cleanup_bytes=12),
        runtime_evidence_scope='separate-process-after-startup',runtime_file_sha256=runtime['disk_sha256'],
        blockers=['original-runtime-instance-and-generation','original-object-mapping-lifetime-aliases','incoming-startup-state','set-app-type-effects','set-fmode-effects','sentinel-input-state-and-failure-path'],
        composition_authorized=False,emission_allowed=False)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('evidence',nargs='?',type=Path,default=Path(os.environ.get('RUNNER_TEMP','/tmp'))/'w2l-compiler-measurement');ap.add_argument('--compare',action='store_true');a=ap.parse_args();p=a.evidence
    # Regenerate/check static callback inventory independently before consuming it.
    import subprocess
    subprocess.run(['python' if os.name=='nt' else 'python3',str(ROOT/'research/crt/callback_inventory.py'),str(p),'--compare'],check=True,stdout=subprocess.DEVNULL)
    out=audit((p/'held_crt.exe').read_bytes(),json.loads((p/'crt-callbacks.json').read_text()),json.loads((p/'crt-runtime.json').read_text()))
    out['audit_source_sha256']=sha(Path(__file__).read_bytes());report=p/'crt-composition.json'
    if a.compare:assert json.loads(report.read_text())==out
    else:report.write_text(json.dumps(out,indent=2)+'\n')
    print('COMPOSITION_BLOCKED',out['blockers'])
if __name__=='__main__':main()
