"""Bind unchanged caller; separate authored /MD and /MT ownership probes."""
import argparse,hashlib,json,os,struct,subprocess
from pathlib import Path
from onexit_inventory import inventory
REPO=Path(__file__).resolve().parents[2];SOURCE=REPO/'research/crt'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def bind(root):
    inherited=inventory(root);b=(root/'held_crt.exe').read_bytes();u=lambda p:struct.unpack_from('<I',b,p)[0]
    o=u(60)+24;t=o+224;sections=[struct.unpack_from('<IIII',b,t+40*i+8) for i in range(4)]
    def raw(r,n=4):
        found=[p+r-v for size,v,count,p in sections if v<=r and r+n<=v+min(size,count)]
        assert len(found)==1 and found[0]+n<=len(b);return found[0]
    def read(r,n):return b[raw(r,n):raw(r,n)+n]
    def string(r):
        data=bytearray()
        for i in range(256):
            v=read(r+i,1)[0]
            if not v:return data.decode('ascii')
            data.append(v)
        raise ValueError('unterminated')
    windows={0x1043:'e8780600008bf0e8b70c00006a018930e888030000',0x16c0:'33c0c3',0x1d06:'ff25a8204000'}
    for r,h in windows.items():assert read(r,len(bytes.fromhex(h)))==bytes.fromhex(h)
    sites=[];r=u(o+136);end=r+u(o+140)
    while r<end:
        page,n=struct.unpack('<II',read(r,8));assert n>=8 and n%4==0 and r+n<=end
        for i in range(8,n,2):
            v=struct.unpack('<H',read(r+i,2))[0]
            if v>>12==3:sites.append(page+(v&4095))
        r+=n
    assert 0x1d08 in sites
    for start,h in windows.items():assert all(s==0x1d08 for s in sites if s<start+len(bytes.fromhex(h)) and start<s+4)
    imports={};directory=u(o+104)
    for j in range(32):
        orig,stamp,chain,dll,iat=struct.unpack('<IIIII',read(directory+20*j,20))
        if not any((orig,stamp,chain,dll,iat)):break
        for k in range(256):
            value=struct.unpack('<I',read(orig+4*k,4))[0]
            if not value:break
            assert value<0x80000000;imports[iat+4*k]=string(dll)+'!'+string(value+2)
        else:raise ValueError('thunks')
    else:raise ValueError('descriptors')
    assert imports[0x20a8]=='api-ms-win-crt-stdio-l1-1-0.dll!__p__commode'
    return dict(pe_sha256=inherited['pe_sha256'],windows={hex(k):v for k,v in windows.items()},iat=0x20a8,imported=imports[0x20a8],stored_scalar=0,prior_effects_closed=False,emission_allowed=False)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('evidence',nargs='?',type=Path,default=Path(os.environ.get('RUNNER_TEMP','/tmp'))/'w2l-compiler-measurement');ap.add_argument('--compare',action='store_true');a=ap.parse_args();root=a.evidence.resolve();binding=bind(root)
    sources={n:sha(SOURCE/n) for n in ['commode_probe.c','commode_model.py','test_commode_model.py','check_commode.py']};report=root/'crt-commode.json'
    if not a.compare:
        assert os.name=='nt';observations=[]
        for mode in ['MD','MT']:
            probe=root/f'crt_commode_{mode}.exe'
            p=subprocess.run(['cl','/nologo','/W4','/WX','/O2','/'+mode,str(SOURCE/'commode_probe.c'),f'/Fe{probe}'],cwd=root,capture_output=True,timeout=60)
            (root/f'crt-commode-{mode}-build.txt').write_bytes(p.stdout+p.stderr);assert p.returncode==0,(p.stdout,p.stderr)
            for trial in range(2):
                p=subprocess.run([str(probe)],cwd=root,capture_output=True,timeout=15)
                (root/f'crt-commode-{mode}-{trial}.txt').write_bytes(p.stdout+p.stderr);assert p.returncode==0,(p.returncode,p.stdout,p.stderr)
                values=list(map(int,p.stdout.split()));assert len(values)==9
                pointer,again,thread,base,old,value,thread_value,restored,code=values
                assert pointer==again==thread and pointer%4==0 and pointer>=base and value==thread_value==code==0 and old==restored
                tag,path=p.stderr.decode().strip().split('\t');assert tag=='OWNER';owner=Path(path)
                env=dict(os.environ,COMMODE_OWNER=str(owner));v=subprocess.run(['powershell','-NoProfile','-Command','(Get-Item -LiteralPath $env:COMMODE_OWNER).VersionInfo.FileVersion'],env=env,capture_output=True,timeout=30);assert v.returncode==0 and not v.stderr
                # These are measured hypotheses for this fixed /MD or /MT build only.
                assert owner.name.lower()==('ucrtbase.dll' if mode=='MD' else probe.name.lower())
                observations.append(dict(mode=mode,trial=trial,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex(),exit=p.returncode,values=values,owner_path=str(owner),owner_sha256=sha(owner),owner_version=v.stdout.decode().strip(),probe_sha256=sha(probe)))
        report.write_text(json.dumps(dict(binding=binding,sources=sources,observations=observations,original_program_translation=False,complete_startup_proof=False,emission_allowed=False),indent=2)+'\n')
    out=json.loads(report.read_text());assert out['binding']==binding and out['sources']==sources and not out['emission_allowed'] and not out['complete_startup_proof']
    assert [(x['mode'],x['trial']) for x in out['observations']]==[('MD',0),('MD',1),('MT',0),('MT',1)]
    for x in out['observations']:
        assert x['probe_sha256']==sha(root/f"crt_commode_{x['mode']}.exe") and x['exit']==0
        assert list(map(int,bytes.fromhex(x['stdout_hex']).split()))==x['values']
        p,q,t,base,old,v,tv,restored,code=x['values'];assert p==q==t and p>=base and v==tv==code==0 and old==restored
        assert x['owner_sha256'] and (x['owner_version'] if x['mode']=='MD' else x['owner_sha256']==x['probe_sha256'])
    print('COMMODE: unchanged caller bound; four isolated process observations; no startup closure')
if __name__=='__main__':main()
