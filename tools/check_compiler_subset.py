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

def fixture(program=code):
    b = image()
    assert len(program) <= 512
    b[0x400:0x400+len(program)] = program
    struct.pack_into('<I',b,0x180,len(program))
    struct.pack_into('<HH',b,0x808,0x3004,0x300c)
    return b

converter = Path('target/debug/w2l').resolve()
with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp);pe=root/'input.exe';rs=root/'output.rs'
    def convert(b):
        pe.write_bytes(b)
        return subprocess.run([str(converter),str(pe),str(rs)],capture_output=True,timeout=15)
    positives=[(None,None,0),(0x413,8,99),(0x420,13,99),(0x425,6,99),(0x420,0x80,99),(0x420,0xff,99),(0x447,12,99)]
    def execute(b,expected):
        p=convert(b);assert p.returncode==0,p.stderr
        first=rs.read_bytes();assert convert(b).returncode==0 and rs.read_bytes()==first
        native=root/'native'
        subprocess.run(['rustc','-D','warnings',str(rs),'-o',str(native)],check=True,capture_output=True)
        with (root/'stdout').open('wb') as out,(root/'stderr').open('wb') as err:
            p=subprocess.run([str(native)],stdout=out,stderr=err,timeout=15)
        assert (p.returncode,(root/'stdout').read_bytes(),(root/'stderr').read_bytes())==(expected,b'Hello',b'')
    for at,value,expected in positives:
        b=fixture()
        if at is not None:b[at]=value
        execute(b,expected)
    # Each mutation independently targets a policy boundary; no repair of rejected bytes.
    bads=[(0x42a,0x56),(0x400,0x57),(0x42a,0x5f),(0x431,0x90),(0x41d,16),
          (0x401,0x66),(0x409,2),(0x402,65),(0x402,0),(0x40b,0x14),
          (0x403,0xb8),(0x407,0x41),(0x417,0xff),(0x421,0x74),
          (0x422,0xff),(0x423,0x90),(0x445,0x45),(0x447,10),
          (0x448,0x5e),(0x414,0x89),(0x660,10)]
    for at,value in bads:
        b=fixture();b[at]=value
        rs.write_text('preserve')
        p=convert(b)
        assert p.returncode==1,(hex(at),p.stderr)
        assert rs.read_text()=='preserve'
    # Independently written literal layout: no production decoder or state helper.
    third = bytes.fromhex('56 6a05 6860204000 6a01 ff1500204000 6a03 6a05 6a07 8bf0 e823000000 83c418 83f80f 7509 83fe05 7504 33c0 5e c3 b863000000 5e c3') + b'\xcc'*11 + bytes.fromhex('8b442404 03442408 0344240c c3')
    assert len(third)==77 and third[0x1d:0x20]==bytes.fromhex('83c418')
    execute(fixture(third),0)

    # Small test-only label fixups; expected arithmetic/output is specified below.
    def composed(blocks):
        result=bytearray(code[:16]); labels={}; calls=[]
        for label,parts in blocks:
            labels[label]=len(result)
            for part in parts:
                if isinstance(part,tuple):
                    calls.append((len(result),part[0]));result.extend(b'\xe8'+bytes(4))
                else:result.extend(bytes.fromhex(part))
        for at,label in calls:
            assert labels[label]>at
            struct.pack_into('<i',result,at+1,labels[label]-(at+5))
        return result
    nested = composed([
        ('entry',['6a00 6a00 6a00',('outer',),'83c418 5e c3']),
        ('outer',['6a00 6a00 6a00 6a09 6a08 6a07',('leaf',),'83c418',
                  '6a00 6a00 6a00 6a03 6a02 6a01',('leaf',),'83c418 c3']),
        ('leaf',['8b442404 03442408 0344240c c3'])])
    # leaf(7,8,9)=24, then the same leaf(1,2,3)=6 at nested depth2.
    execute(fixture(nested),6)
    new_bad=[]
    # Exact new forms: reject neighboring offsets, encodings, registers/prefixes.
    for at,value in [(0x1d,0x66),(0x1e,0xc0),(0x1f,0x19),(0x1f,0x1c),
                     (0x48,0x66),(0x48,0x01),(0x49,0x45),(0x4a,0x25),
                     (0x4b,0x0b),(0x4b,0x0d),(0x4b,0x10),(0x4b,0xfc)]:
        b=bytearray(third);b[at]=value;new_bad.append((b,None))
    # Five words leaves a Data word above saved ESI; the six-word baseline
    # mutation crosses the saved word. Both must fail state validation.
    b=bytearray(third);b[0x1f]=20;new_bad.append((b,'saved ESI ownership'))
    b=bytearray(code);b[0x1d]=24;new_bad.append((b,'cleanup ownership'))
    def reject_program(entry,leaf,diagnostic,outer=None):
        blocks=[('entry',entry)]
        if outer is not None:blocks.append(('outer',outer))
        blocks.append(('leaf',[leaf]))
        new_bad.append((composed(blocks),diagnostic))
    # First clean the output's three arguments using two padding words.
    clean='6a00 6a00 83c414'
    reject_program([clean,('leaf',),'5e c3'],'b807000000 0344240c c3','argument bounds')
    reject_program([clean,'56 6a05 6a07',('leaf',),'5e c3'],
                   'b807000000 0344240c c3','argument ownership')
    reject_program([clean,('outer',),'5e c3'],'b807000000 0344240c c3',
                   'argument ownership',['6a05 6a07',('leaf',),'c3'])
    reject_program([('outer',),'5e c3'],'b807000000 0344240c c3',
                   'argument ownership',['6a07',('leaf',),'c3'])
    # Third word is the genuine relocated output pointer, not an Integer.
    reject_program(['6a07',('leaf',),'5e c3'],'b807000000 0344240c c3','scalar required')
    # MOV does not repair unknown flags after six-word ADD ESP cleanup.
    reject_program(['6a03 6a05 6a07',('leaf',),'83c418 b800000000 7502 5e c3 5e c3'],
                   '8b442404 03442408 0344240c c3','unknown branch flags')
    reject_program(['6a03 6a05 6a07',('leaf',),'83c418 5e c3'],
                   '6a00 6a00 6a00 6a00 6a00 83c418 c3','cleanup ownership')
    # EAX=7 makes JNZ untaken. Its invalid third-argument path must still reject.
    reject_program(['6a03 6a05 6a07',('leaf',),'83c418 5e c3'],
                   '8b442404 83f807 7505 0344240c c3 56 0344240c c3','argument return boundary')
    for program,diagnostic in new_bad:
        rs.write_text('preserve')
        p=convert(fixture(program))
        assert p.returncode==1,(program.hex(),p.stderr)
        assert rs.read_text()=='preserve'
        if diagnostic is not None:assert diagnostic in p.stderr.decode(),p.stderr
    for end in [0x1e,0x1f,0x49,0x4a,0x4b]:
        b=fixture(third);struct.pack_into('<I',b,0x180,end)
        rs.write_text('preserve');p=convert(b)
        assert p.returncode==1 and rs.read_text()=='preserve',p.stderr
print(f'compiler-shaped production: {len(positives)+2} deterministic native cases, {len(bads)} existing-policy rejection slots and {len(new_bad)} new rejections plus 5 executable-bound truncations; separate from unchanged MSVC evidence')
