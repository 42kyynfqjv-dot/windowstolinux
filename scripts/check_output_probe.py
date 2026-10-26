"""Check authored layout independently; optionally execute original Windows PE."""
import struct
import subprocess
import sys
from pathlib import Path
from make_output_probe import output_probe

b = output_probe()
u32 = lambda at: struct.unpack_from('<I', b, at)[0]
assert len(b) == 2048 and b[0x86:0x88] == b'\x03\0'
assert (u32(0x100), u32(0x104)) == (0x3000, 40)
assert (u32(0x158), u32(0x15c)) == (0x3050, 8)
assert [u32(i) for i in range(0x600, 0x628, 4)] == [0x3040, 0, 0, 0x3060, 0x3050, 0, 0, 0, 0, 0]
assert b[0x640:0x648] == b[0x650:0x658] == bytes.fromhex('8030000000000000')
assert b[0x660:0x66b] == b'msvcrt.dll\0' and b[0x680:0x689] == b'\0\0_write\0'
assert b[0x400:0x405] == b'Hello'
assert b[0x200:0x20f] == bytes.fromhex('680500000068002040006801000000')
assert b[0x20f:0x215] == bytes.fromhex('ff1550304000')
assert b[0x226:0x228] == b'\x74\x06' and b[0x22e:0x234] == b'\xb8\0\0\0\0\xc3'
print('Output probe: literal PE/import/argument/branch layout verified')
if '--execute-windows' in sys.argv:
    assert sys.platform == 'win32'
    exe = Path('output-probe.exe').resolve()
    exe.write_bytes(b)
    with open('output-probe.stdout', 'wb') as out, open('output-probe.stderr', 'wb') as err:
        result = subprocess.run([str(exe)], stdout=out, stderr=err, timeout=15)
    out, err = Path('output-probe.stdout').read_bytes(), Path('output-probe.stderr').read_bytes()
    print(f'Original output probe: stdout={out.hex()} stderr={err.hex()} exit={result.returncode}')
    assert (out, err, result.returncode) == (b'Hello', b'', 0)
