"""Bind test-only proof to an exact trusted compiler profile; never emit code."""
import argparse,hashlib,json,struct
from pathlib import Path
from model import prove
CODE=bytes.fromhex('83ec088d04246a03506808204000ff15002040008bc885c97509b8c800000083c408c383f9417609b8cb00000083c408c383f9027609b8c900000083c408c38b1424568d42d06683f809772b0fb7d283ea3083f90275198b7424068d46d06683f80977138d14920fb7c68d52e88d14508bc25e83c408c3b8ca0000005e83c408c3')
def main():
    ap=argparse.ArgumentParser();ap.add_argument('evidence',type=Path);ap.add_argument('--compare',action='store_true');a=ap.parse_args();root=a.evidence
    b=(root/'input.exe').read_bytes();sha=lambda b:hashlib.sha256(b).hexdigest()
    prior=json.loads((root/'input-contract.json').read_text(encoding='utf-8'))
    assert sha(b)==prior['pe_sha256']
    p=struct.unpack_from('<I',b,60)[0];o=p+24;t=o+struct.unpack_from('<H',b,p+20)[0]
    assert struct.unpack_from('<H',b,p+4)[0]==0x14c and struct.unpack_from('<H',b,o)[0]==0x10b
    assert struct.unpack_from('<I',b,o+28)[0]==0x400000 and struct.unpack_from('<I',b,o+16)[0]==0x1000
    sections=[struct.unpack_from('<IIII',b,t+i*40+8) for i in range(struct.unpack_from('<H',b,p+6)[0])]
    def read(r,n):
        hits=[f+r-v for size,v,raw,f in sections if v<=r and r+n<=v+min(size,raw)]
        assert len(hits)==1 and hits[0]+n<=len(b);return b[hits[0]:hits[0]+n]
    def u32(r):return struct.unpack('<I',read(r,4))[0]
    def string(r):
        out=bytearray()
        for i in range(128):
            c=read(r+i,1)[0]
            if not c:return out.decode('ascii')
            out.append(c)
        raise ValueError('name cap')
    assert read(0x1000,len(CODE))==CODE
    assert read(0x2008,20)=='W2L_INPUT\0'.encode('utf-16le')
    directory=struct.unpack_from('<I',b,o+104)[0]
    original,stamp,chain,dll,iat=struct.unpack('<IIIII',read(directory,20))
    assert read(directory+20,20)==bytes(20) and iat==0x2000 and original
    assert string(dll).lower()=='kernel32.dll'
    name=u32(original);assert name<0x80000000 and u32(original+4)==0
    assert string(name+2)=='GetEnvironmentVariableW' and u32(iat)==name and u32(iat+4)==0
    reloc,size=struct.unpack_from('<II',b,o+136);pos=0;sites=[]
    while pos<size:
        page,n=struct.unpack('<II',read(reloc+pos,8));assert n>=8 and n%2==0 and pos+n<=size
        for off in range(8,n,2):
            word=struct.unpack('<H',read(reloc+pos+off,2))[0]
            if word>>12:
                assert word>>12==3;sites.append(page+(word&4095))
        pos+=n
    assert sorted(sites)==[0x100a,0x1010]
    model=prove();out=dict(pe_sha256=sha(b),code_sha256=sha(CODE),proof=model,
        sources={n:sha((Path(__file__).parent/n).read_bytes()) for n in ['model.py','check_model.py']},
        scope='exact-profile test-only conditional proof',emission_allowed=False)
    path=root/'input-model.json'
    if a.compare:assert json.loads(path.read_text(encoding='utf-8'))==json.loads(json.dumps(out))
    else:path.write_text(json.dumps(out,indent=2)+'\n')
    print('INPUT_MODEL: complete result intervals, guarded reads, production blocked')
if __name__=='__main__':main()
