"""Exact unchanged authored image binding for SUB-542; no execution permission."""
import hashlib
import json
from pathlib import Path
import struct
import sys

# Literal disassembly bytes read independently of production decoding/model expectations.
BODIES = {
    0x13e0: '558bec803da9304000007404b0015dc3568b750885f6740583fe01757ce85e08000085c0742b85f6752768ac304000e8f808000083c40485c0751168b8304000e8e708000083c40485c0744132c05e5dc3c705ac304000ffffffffc705b0304000ffffffffc705b4304000ffffffffc705b8304000ffffffffc705bc304000ffffffffc705c0304000ffffffffc605a930400001b0015e5dc36a05e840030000cc',
    0x15c0: '558bec833dac304000ff568b750856751be84207000033c983c40485c00f44cef7d95e1bc9f7d98d41ff5dc368ac304000e81c07000033c983c40885c00f44cef7d95e1bc9f7d98d41ff5dc3',
    0x1c60: '33c03905983040000f95c0c3',
    0x17c0: '558bec8b4d08cd295dc3',
}

def inventory(root):
    b=(root/'held_crt.exe').read_bytes()
    record=next(r for r in json.loads((root/'heldout-x86.json').read_text()) if r['kind']=='held_crt')
    assert hashlib.sha256(b).hexdigest()==record['sha256'] and not record['conversion_accepted']
    def u(p):return struct.unpack_from('<I',b,p)[0]
    pe=u(60);opt=pe+24;table=opt+struct.unpack_from('<H',b,pe+20)[0]
    assert b[pe:pe+4]==b'PE\0\0' and struct.unpack_from('<H',b,pe+4)[0]==0x14c
    assert struct.unpack_from('<H',b,opt)[0]==0x10b and u(opt+28)==0x400000
    sections=[struct.unpack_from('<IIII',b,table+40*i+8) for i in range(struct.unpack_from('<H',b,pe+6)[0])]
    def raw(rva,n=4):
        found=[pos+rva-start for vs,start,size,pos in sections if start<=rva and rva+n<=start+min(vs,size)]
        assert len(found)==1 and found[0]+n<=len(b)
        return found[0]
    def read(rva,n):
        p=raw(rva,n);return b[p:p+n]
    def word(rva):return u(raw(rva))
    def string(rva):
        out=bytearray()
        for i in range(256):
            c=read(rva+i,1)[0]
            if not c:return out.decode('ascii')
            out.append(c)
        raise ValueError('string cap')
    reloc=u(opt+136);end=reloc+u(opt+140);sites=set()
    while reloc<end:
        page,n=struct.unpack('<II',read(reloc,8));assert n>=8 and n%4==0 and reloc+n<=end
        for i in range(8,n,2):
            v=struct.unpack('<H',read(reloc+i,2))[0]
            assert v>>12 in (0,3)
            if v>>12==3:
                site=page+(v&4095);assert site not in sites;raw(site);sites.add(site)
        reloc+=n
    bound=[]
    for start,h in BODIES.items():
        code=bytes.fromhex(h);assert read(start,len(code))==code,hex(start)
        required=[]
        for i in range(len(code)-3):
            value=int.from_bytes(code[i:i+4],'little')
            if 0x403000<=value<0x404000:
                assert start+i in sites;required.append(start+i)
        assert all(site in required for site in sites if site < start+len(code) and start < site+4)
        bound.append(dict(rva=start,size=len(code),sha256=hashlib.sha256(code).hexdigest(),highlow_sites=required))
    assert read(0x104f,9)==bytes.fromhex('6a018930e888030000')
    assert read(0x1067,10)==bytes.fromhex('68d0184000e84f050000') and 0x1068 in sites
    assert word(0x20c8)==0x401030 and 0x20c8 in sites
    imports={};directory=u(opt+104)
    for j in range(32):
        orig,stamp,chain,dll,iat=struct.unpack('<IIIII',read(directory+20*j,20))
        if not any((orig,stamp,chain,dll,iat)):break
        for i in range(256):
            value=word(orig+4*i)
            if not value:break
            assert value<0x80000000
            imports[iat+4*i]=string(dll)+'!'+string(value+2)
        else:raise ValueError('thunk cap')
    else:raise ValueError('import cap')
    targets={}
    for thunk,name in [(0x1d0c,'_initialize_onexit_table'),(0x1d12,'_register_onexit_function'),(0x1d18,'_crt_atexit')]:
        code=read(thunk,6);assert code[:2]==b'\xff\x25' and thunk+2 in sites
        iat=int.from_bytes(code[2:],'little')-0x400000
        assert imports[iat]=='api-ms-win-crt-runtime-l1-1-0.dll!'+name
        targets[hex(thunk)]=dict(iat_rva=iat,imported=imports[iat])
    return dict(pe_sha256=record['sha256'],bodies=bound,thunks=targets,caller_policy=1,
                query_target_rva=0x1c60,query_is_import=False,mode_rva=0x3098,initial_mode=word(0x3098),
                initial_flag=read(0x30a9,1).hex(),initial_tables=read(0x30ac,24).hex(),
                static_local_path='policy 1 selects sentinel stores if initialized flag is zero; registration remains external',
                prior_effects_closed=False,complete_startup_proof=False,emission_allowed=False)

if __name__=='__main__':
    root=Path(sys.argv[1]);out=inventory(root);path=root/'crt-onexit-inventory.json'
    if len(sys.argv)>2:assert json.loads(path.read_text())==out
    else:path.write_text(json.dumps(out,indent=2)+'\n')
    print('ONEXIT_INVENTORY',json.dumps(out))
