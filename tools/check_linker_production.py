"""Production CLI checks using independently authored SUB-515 byte layout."""
from pathlib import Path
import struct
import subprocess
import tempfile
from test_linker_intake import image

converter = Path('target/debug/w2l').resolve()
count = 0
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    exe, output = root/'input.exe', root/'output.rs'
    def check(blob, diagnostic=None, structural=False):
        global count
        exe.write_bytes(blob)
        output.write_text('existing output must survive rejection')
        p = subprocess.run([str(converter), str(exe), str(output)], capture_output=True, timeout=15)
        assert p.returncode == 1, (count, p.returncode, p.stderr)
        assert output.read_text() == 'existing output must survive rejection'
        message = p.stderr.decode()
        assert ('linker intake validated;' in message) == structural, (count, message)
        if diagnostic:
            assert diagnostic in message, (count, message)
        count += 1
    original = image()
    check(original, 'output arguments', True)
    changed = bytearray(original); changed[0x400] = 0x56
    check(changed, 'unsupported instruction', True)
    # Independent mutation expectations. Every one must fail before structural success.
    mutations = [
        (0xde,'H',0),(0xde,'H',0xc540),(0x86,'H',4),(0x96,'H',0x103),(0xd0,'I',0x200000),
        (0xd4,'I',0x180),(0x108,'I',0x2000),(0x148,'I',0x2000),
        (0x1a8,'I',0x201),(0x1b4,'I',0x400),(0x1ac,'I',0x1000),
        (0x19c,'I',0xe0000020),(0x1b4,'I',0xfffffe00),(0xa8,'I',0x1010),
        (0x680,'I',0x2000),(0x68c,'I',0x20fc),(0x600,'I',0x80000001),
        (0x604,'I',1),(0x684,'I',1),(0x694,'I',1),(0x15c,'I',12),
        (0x6d0,'B',77),(0x6c2,'B',88),(0x61c,'I',20),(0x61c,'I',2),
        (0x628,'I',0x641),(0x624,'I',0x2000),(0x620,'I',0),
        (0x620,'I',4097),(0x624,'I',0),(0x620,'I',0xc1),
        (0x804,'I',0),(0x804,'I',8),(0x804,'I',10),(0x804,'I',16),
        (0x800,'I',1),(0x800,'I',0xfffff000),(0x808,'H',0x4001),
        (0x808,'H',0xa001),(0x808,'H',1),(0x80a,'H',0x3001),
        (0x80a,'H',0x3003),(0x80a,'H',0x300e),(0x401,'I',0x402040),
        (0x401,'I',0x3fffff),(0x401,'I',0x401000),
    ]
    for offset, fmt, value in mutations:
        bad = bytearray(original); struct.pack_into('<'+fmt,bad,offset,value)
        check(bad)
    # Compound layouts exercise role mapping and complete-block rules.
    padded = bytearray(original); struct.pack_into('<H',padded,0x80a,0)
    check(padded, 'missing import relocation', True)
    swapped = bytearray(original)
    swapped[0x400:0x600], swapped[0x800:0xa00] = original[0x800:0xa00], original[0x400:0x600]
    struct.pack_into('<I',swapped,0x18c,0x800)
    struct.pack_into('<I',swapped,0x1dc,0x400)
    check(swapped, 'output arguments', True)
    duplicate = bytearray(original)
    struct.pack_into('<I',duplicate,0x1d0,24)
    struct.pack_into('<I',duplicate,0x124,24)
    duplicate[0x80c:0x818] = original[0x800:0x80c]
    check(duplicate, 'relocation page order')
    metadata_target = bytearray(original)
    struct.pack_into('<IIHH',metadata_target,0x800,0x2000,12,0x3000,0)
    check(metadata_target, 'whole range outside linker section')
    for length in range(len(original)):
        check(original[:length])
print(f'production linker checks: 4 structural barriers, {len(mutations)} single mutations, 2 compound rejections, {len(original)} truncations; {count} rejected without output writes')
