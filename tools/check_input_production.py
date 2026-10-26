"""Independently laid-out authored input PE; not the unchanged MSVC artifact."""
import os,struct,subprocess,tempfile
from pathlib import Path
from test_linker_intake import image
CODE=bytes.fromhex('83ec088d04246a03506860204000ff15002040008bc885c97509b8c800000083c408c383f9417609b8cb00000083c408c383f9027609b8c900000083c408c38b1424568d42d06683f809772b0fb7d283ea3083f90275198b7424068d46d06683f80977138d14920fb7c68d52e88d14508bc25e83c408c3b8ca0000005e83c408c3')
def fixture():
    b=image();b[0x400:0x400+len(CODE)]=CODE
    struct.pack_into('<I',b,0x180,len(CODE))
    b[0x660:0x674]='W2L_INPUT\0'.encode('utf-16le')
    struct.pack_into('<I',b,0x68c,0x20e0)
    b[0x6c0:0x6c0+26]=b'\0\0GetEnvironmentVariableW\0'
    b[0x6e0:0x6ed]=b'KERNEL32.dll\0'
    struct.pack_into('<HH',b,0x808,0x300a,0x3010)
    assert len(b)==0xa00
    return b
converter=Path('target/debug/w2l').resolve();rejects=0;cases=0
with tempfile.TemporaryDirectory() as d:
    root=Path(d);pe=root/'in.exe';rs=root/'native.rs';exe=root/'native'
    def convert(b):
        pe.write_bytes(b)
        return subprocess.run([str(converter),str(pe),str(rs)],capture_output=True,timeout=10)
    def native(b,values):
        global cases
        p=convert(b);assert p.returncode==0,p.stderr
        first=rs.read_bytes();assert convert(b).returncode==0 and rs.read_bytes()==first
        p=subprocess.run(['rustc','--edition=2021','-D','warnings',str(rs),'-o',str(exe)],capture_output=True,timeout=60)
        assert p.returncode==0,p.stderr
        for value,expected in values:
            p=subprocess.run([str(exe)],env={} if value is None else {'W2L_INPUT':value},capture_output=True,timeout=10)
            assert (p.returncode,p.stdout,p.stderr)==(expected,b'',b''),(repr(value),p.returncode,expected)
            cases+=1
    native(fixture(),[(None,200),('',200),('7',7),('42',42),('07',7),('99',99),('/',202),(':',202),('9/',202),('😀',202),('100',201),('7'*64,201),('7'*65,203)])
    # Changed valid application semantics must survive lifting. Not template matching.
    b=fixture();b[0x41b]=199;native(b,[(None,199),('42',42)])
    b=fixture();b[0x45a]=4;native(b,[('42',44),('09',0)])
    b=fixture();struct.pack_into('<H',b,0x6c0,65535);native(b,[('7',7)]) # valid search hint
    def reject(b,label):
        global rejects
        rs.write_text('preserve')
        p=convert(b);assert p.returncode==1,(label,p.returncode,p.stderr)
        assert rs.read_text()=='preserve',label
        rejects+=1
    for off,value in [
        (0x407,2),(0x408,0x51),(0x418,0x76),(0x419,0x25), # args/failure guard
        (0x434,0x77),(0x454,1), # oversize/second-word initialization
        (0x45a,0),(0x45a,3),(0x45a,7),(0x45a,8),(0x45a,255), # protected/full bounds
        (0x442,0x50),(0x472,0x50),(0x47c,0x50),(0x475,20), # save/return/cleanup
        (0x44a,0x76),(0x462,0x76), # invalid digits admitted
        (0x446,0x67),(0x414,0x66),(0x40e,0x9a),(0x400,0x90), # unsupported forms
        (0x419,255),(0x419,1),(0x435,0), # cycle/middle/unsafe join
        (0x660,ord('X')),(0x672,ord('X')),(0x6c2,ord('X')),(0x6e0,ord('x')),
    ]:
        b=fixture();b[off]=value;reject(b,hex(off))
    for off,value in [
        (0x40a,0x402000),(0x40a,0x401000),(0x40a,0x4020fe),(0x410,0x402060),
        (0x680,0x2000),(0x680,0x20fe),(0x68c,0x20c0),(0x690,0x20b0),
        (0x600,0x80000001),(0x604,1),(0x6b4,1),(0x6b0,0x20c2),
        (0x180,128),(0x180,130),(0x188,0x100),(0x18c,0x600),(0x1c4,0xc0000040),
        (0xa8,0x1001),(0x800,0x2000),(0x804,8),(0xd0,0xfffff000),
    ]:
        b=fixture();struct.pack_into('<I',b,off,value);reject(b,hex(off))
    for word in [0,0x300b,0x3010,0xa00a,0x3fff]:
        b=fixture();struct.pack_into('<H',b,0x808,word);reject(b,hex(word))
    for directory in [0,2,3,4,7,8,9,10,11,13,14,15]:
        b=fixture();struct.pack_into('<II',b,0xf8+8*directory,0x2060,4);reject(b,('directory',directory))
    for end in [0,2,60,64,0x80,0x98,0x178,0x1f0,0x3ff,0x400,0x480,0x600,0x6c0,0x6ec,0x800,0x809,0x9ff]:
        reject(fixture()[:end],('truncated',end))
print(f'INPUT PRODUCTION: {cases} authored native executions; {rejects} rejected images; unchanged MSVC evidence separate')
