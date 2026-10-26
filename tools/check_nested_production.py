"""Literal independent nested bytes, production CLI/native checks; no model oracle."""
from pathlib import Path
import struct, subprocess, tempfile
from test_linker_intake import image

# Fixed observed code layout, with original two relocations and Hello buffer shell.
ENTRY=bytes.fromhex('56 6a05 6860204000 6a01 ff1500204000 6a05 6a07 8bf0 e835000000 83c414 83f80f 7509 83fe05 7504 33c0 5e c3 b863000000 5e c3')
INNER=bytes.fromhex('8b442404 03442408 c3')
OUTER=bytes.fromhex('ff742408 ff742408 e8e3ffffff 83c408 83f80c 7406 b863000000 c3 c744240803000000 c74424040c000000 e9c0ffffff')
CODE=ENTRY+b'\xcc'*(0x40-len(ENTRY))+INNER+b'\xcc'*7+OUTER
assert len(CODE)==0x80
converter=Path('target/debug/w2l').resolve()
def fixture(code):
    b=image();b[0x400:0x400+len(code)]=code
    struct.pack_into('<I',b,0x180,len(code));struct.pack_into('<HH',b,0x808,0x3004,0x300c)
    return b
with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp);pe=root/'input.exe';rs=root/'native.rs'
    def convert(code):
        pe.write_bytes(fixture(code))
        return subprocess.run([str(converter),str(pe),str(rs)],capture_output=True,timeout=15)
    def execute(code,expected):
        p=convert(code);assert p.returncode==0,p.stderr
        source=rs.read_bytes();assert convert(code).returncode==0 and rs.read_bytes()==source
        for text in ['Op::CopyArgument','Op::StoreFirst','Op::StoreSecond','Op::Tail(4160)','Op::Equal(4203)']:
            assert text.encode() in source,text
        native=root/'native'
        subprocess.run(['rustc','-D','warnings',str(rs),'-o',str(native)],check=True,capture_output=True)
        with (root/'out').open('wb') as out,(root/'err').open('wb') as err:
            p=subprocess.run([str(native)],stdout=out,stderr=err,timeout=15)
        assert (p.returncode,(root/'out').read_bytes(),(root/'err').read_bytes())==(expected,b'Hello',b'')
    execute(CODE,0)
    b=bytearray(CODE);b[0x13]=8;execute(b,99)
    rejected=0
    def reject(code,message=None):
        global rejected
        rs.write_text('preserve');p=convert(code)
        assert p.returncode==1 and rs.read_text()=='preserve',(code.hex(),p.stderr)
        if message:assert message in p.stderr.decode(),p.stderr
        rejected+=1
    for at,val in [(0x50,0x66),(0x51,0x75),(0x52,0x25),(0x53,4),(0x57,12),
                   (0x63,0x76),(0x64,0xff),(0x6b,0x66),(0x6c,0x45),(0x6d,0x25),
                   (0x6e,12),(0x6f,4),(0x76,8),(0x77,13),(0x7b,0xeb)]:
        b=bytearray(CODE);b[at]=val;reject(b)
    # Complete static graph catches direct recursion, tail cycles, target interiors
    # and call continuations masquerading as routine entries.
    for site,target in [(0x58,0x1050),(0x7b,0x1050),(0x58,0x1041),(0x58,0x105d),(0x7b,0x5000)]:
        b=bytearray(CODE);struct.pack_into('<i',b,site+1,target-(0x1000+site+5));reject(b)
    # Unsupported bytes on the untaken failure path still reject.
    b=bytearray(CODE);b[0x65]=0x90;reject(b)
    # Store after an unbalanced push and copy without a callee frame.
    b=bytearray(CODE);b[0x65:0x6a]=bytes.fromhex('6a00 6a00 56');reject(b)
    b=bytearray(CODE);b[0x10:0x14]=bytes.fromhex('ff742408');reject(b)
    # MOV preserves the unknown flags from cleanup: JE must not assume ZF.
    b=bytearray(CODE);b[0x60:0x63]=bytes.fromhex('b800000000')
    struct.pack_into('<i',b,0x7e,0x1040-(0x1000+0x7d+5))
    reject(b,'unknown branch flags')
    for end in [0x51,0x52,0x53,0x59,0x5a,0x5b,0x5c,0x64,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7c,0x7d,0x7e,0x7f]:
        reject(CODE[:end])
print(f'nested production: 2 deterministic native cases, {rejected} CLI rejections; separate from MSVC Windows/Linux evidence')
