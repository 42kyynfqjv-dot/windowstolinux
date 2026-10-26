"""Authored literal MSVC-shaped code: production CLI/native regression tests.
Not the real compiler artifact; compiler/measure.py supplies that separate gate.
"""
from pathlib import Path
import struct
import subprocess
import tempfile
from test_linker_intake import image

code = bytes.fromhex('56 6a05 6860204000 6a01 ff1500204000 6a05 6a07 8bf0 e825000000 83c414 83f80c 7509 83fe05 7504 33c0 5e c3 b863000000 5e c3') + b'\xcc'*13 + bytes.fromhex('8b442404 03442408 c3')
assert len(code) == 73

def fixture():
    b = image()
    b[0x400:0x449] = code
    struct.pack_into('<I',b,0x180,73)
    struct.pack_into('<HH',b,0x808,0x3004,0x300c)
    return b

converter = Path('target/debug/w2l').resolve()
with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp);pe=root/'input.exe';rs=root/'output.rs'
    def convert(b):
        pe.write_bytes(b)
        return subprocess.run([str(converter),str(pe),str(rs)],capture_output=True,timeout=15)
    positives=[(None,None,0),(0x413,8,99),(0x420,13,99),(0x425,6,99),(0x420,0x80,99),(0x420,0xff,99)]
    for at,value,expected in positives:
        b=fixture()
        if at is not None:b[at]=value
        p=convert(b);assert p.returncode==0,p.stderr
        first=rs.read_bytes();assert convert(b).returncode==0 and rs.read_bytes()==first
        native=root/'native'
        subprocess.run(['rustc','-D','warnings',str(rs),'-o',str(native)],check=True,capture_output=True)
        with (root/'stdout').open('wb') as out,(root/'stderr').open('wb') as err:
            p=subprocess.run([str(native)],stdout=out,stderr=err,timeout=15)
        assert (p.returncode,(root/'stdout').read_bytes(),(root/'stderr').read_bytes())==(expected,b'Hello',b'')
    # Each mutation independently targets a policy boundary; no repair of rejected bytes.
    bads=[(0x42a,0x56),(0x400,0x57),(0x42a,0x5f),(0x431,0x90),(0x41d,16),
          (0x401,0x66),(0x409,2),(0x402,65),(0x402,0),(0x40b,0x14),
          (0x403,0xb8),(0x407,0x41),(0x417,0xff),(0x421,0x74),
          (0x422,0xff),(0x423,0x90),(0x445,0x45),(0x447,12),
          (0x448,0x5e),(0x414,0x89),(0x660,10)]
    for at,value in bads:
        b=fixture();b[at]=value
        rs.write_text('preserve')
        p=convert(b)
        assert p.returncode==1,(hex(at),p.stderr)
        assert rs.read_text()=='preserve'
print('compiler-shaped production: 6 deterministic native cases, 21 rejected mutations; separate from unchanged MSVC evidence')
