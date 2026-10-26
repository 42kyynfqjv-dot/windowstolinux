"""Installed runtime bytes stay transient; publish identity and boundary findings only."""
import argparse, hashlib, json, os, struct, subprocess, tempfile
from pathlib import Path
from check_commode import bind
ROOT=Path(__file__).resolve().parents[2]
def sha(b):return hashlib.sha256(b).hexdigest()
def normalized(b,rva,n,base):
    def u(p):return struct.unpack_from('<I',b,p)[0]
    pe=u(60);assert b[:2]==b'MZ' and b[pe:pe+4]==b'PE\0\0' and struct.unpack_from('<H',b,pe+4)[0]==0x14c
    opt=pe+24;assert struct.unpack_from('<H',b,opt)[0]==0x10b
    count=struct.unpack_from('<H',b,pe+6)[0];table=opt+struct.unpack_from('<H',b,pe+20)[0]
    sections=[struct.unpack_from('<IIII',b,table+40*i+8) for i in range(count)]
    def raw(r,n):
        hits=[p+r-v for size,v,length,p in sections if v<=r and r+n<=v+min(size,length)]
        assert len(hits)==1 and hits[0]+n<=len(b);return hits[0]
    start=raw(rva,n);data=bytearray(b[start:start+n]);delta=(base-u(opt+28))&0xffffffff
    rr=u(opt+136);end=rr+u(opt+140);sites=[]
    while rr<end:
        p=raw(rr,8);page,size=struct.unpack_from('<II',b,p);assert size>=8 and size%2==0 and rr+size<=end
        p=raw(rr,size)
        for j in range(8,size,2):
            word=struct.unpack_from('<H',b,p+j)[0];kind=word>>12;site=page+(word&4095)
            if kind==0:continue
            assert kind==3
            if site<rva+n and rva<site+4:
                assert rva<=site and site+4<=rva+n and all(abs(site-x)>=4 for x in sites)
                off=site-rva;struct.pack_into('<I',data,off,(struct.unpack_from('<I',data,off)[0]+delta)&0xffffffff);sites.append(site)
        rr+=size
    assert rr==end
    return bytes(data),sites,u(opt+56)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('evidence',nargs='?',type=Path,default=Path(os.environ.get('RUNNER_TEMP','/tmp'))/'w2l-compiler-measurement');ap.add_argument('--compare',action='store_true');a=ap.parse_args();root=a.evidence.resolve()
    sources={s:sha((ROOT/s).read_bytes()) for s in ['research/crt/runtime_probe.c','research/crt/check_runtime.py','examples/runtime_boundary.rs']};binding=bind(root);report=root/'crt-runtime.json'
    if not a.compare:
        assert os.name=='nt'
        exe=root/'crt_runtime_probe.exe'
        cmd=['cl','/nologo','/W4','/WX','/O2','/MD',str(ROOT/'research/crt/runtime_probe.c'),f'/Fe{exe}']
        p=subprocess.run(cmd,cwd=root,capture_output=True,timeout=60);(root/'crt-runtime-build.txt').write_bytes(p.stdout+p.stderr);assert p.returncode==0
        subprocess.run(['cargo','build','--locked','--example','runtime_boundary'],cwd=ROOT,check=True)
        with tempfile.TemporaryDirectory() as tmp:
            code=Path(tmp)/'code.bin'
            p=subprocess.run([str(exe),str(code)],capture_output=True,timeout=15)
            (root/'crt-runtime-probe.txt').write_bytes(p.stdout+p.stderr);assert p.returncode==0
            base,rva,n,size,machine=map(int,p.stdout.split());assert machine==332 and 0<n<=4096 and base+rva+n<=2**32
            path=p.stderr.decode().strip();assert path.startswith('\\\\?\\')
            disk=Path(path).read_bytes();loaded=code.read_bytes();expected,sites,disk_size=normalized(disk,rva,n,base)
            assert len(loaded)==n and loaded==expected and size==disk_size
            q=subprocess.run([str(ROOT/'target/debug/examples/runtime_boundary.exe'),str(code),str(base+rva)],capture_output=True,timeout=15);assert q.returncode==0 and not q.stderr
            leaf=None
            if loaded[:1]==b'\xb8' and loaded[5:6]==b'\xc3':
                value=struct.unpack_from('<I',loaded,1)[0]
                assert base<=value and value+4<=base+size
                prior=json.loads((root/'crt-accessor.json').read_text())
                assert all(o['owner_sha256']==sha(disk) and o['rows'][0][1]-o['rows'][0][5]==value-base for o in prior['observations'])
                leaf=dict(length=6,destination='EAX',value=value,object_rva=value-base,
                          version=prior['observations'][0]['owner_version'],separate_pointer_observations_agree=True)
            result=dict(leaf=leaf,binding=binding,sources=sources,probe_sha256=sha(exe.read_bytes()),base=base,rva=rva,size=size,machine=machine,canonical_path=path,disk_sha256=sha(disk),window_size=n,loaded_window_sha256=sha(loaded),relocation_sites=sites,normalized_match=True,boundary=q.stdout.decode().splitlines(),effect_proof=False,emission_allowed=False)
            report.write_text(json.dumps(result,indent=2)+'\n')
    r=json.loads(report.read_text());assert r['sources']==sources and r['binding']==binding and r['machine']==332 and r['normalized_match'] is True and r['effect_proof'] is False and r['emission_allowed'] is False
    assert r['probe_sha256']==sha((root/'crt_runtime_probe.exe').read_bytes()) and 0<r['window_size']<=4096
    print('RUNTIME_BOUNDARY',r['boundary'])
if __name__=='__main__':main()
