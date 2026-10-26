"""Independent expected observations through production CLI and original Windows."""
import os
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from make_output_probe import output_probe
from make_pe32_fixture import put


def fixture(payload, skip=False, helper=False):
    b = bytearray(output_probe())
    b[0x400:0x440] = payload + bytes(64-len(payload))
    put(b, 0x1a8, 64, 4)
    put(b, 0x201, len(payload), 4)
    put(b, 0x222, len(payload), 4)
    code = bytes(b[0x200:0x234])
    if skip:
        code = b'\x31\xc0\x74\x34' + code + b'\xb8\0\0\0\0\xc3'
    if helper == 'shared':
        code = bytes.fromhex('31c0 740b e811000000 b800000000 c3 e806000000 b800000000 c3') + code
    elif helper:
        code = b'\xe8\x06\0\0\0\xb8\0\0\0\0\xc3' + code
    b[0x200:0x300] = bytes(256)
    b[0x200:0x200+len(code)] = code
    return b

CASES = [('hello', b'Hello', False, False), ('changed', b'World', False, False),
         ('one', b'!', False, False), ('max', b'A'*64, False, False),
         ('untaken', b'Hello', True, False), ('helper', b'Hello', False, True), ('shared', b'Hello', False, 'shared')]
windows = '--windows' in sys.argv
converter = Path('target/debug/w2l').resolve()
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    exe, source, elf = root/'fixture.exe', root/'generated.rs', root/'generated'
    rejected = 0
    def convert(data, accepted):
        global rejected
        if not accepted: rejected += 1
        exe.write_bytes(data)
        p = subprocess.run([str(converter), str(exe), str(source)], capture_output=True)
        assert (p.returncode == 0) == accepted, (accepted, p.stderr, data[0x200:0x240].hex())
    for name, payload, skip, helper in CASES:
        b = fixture(payload, skip, helper)
        exe.write_bytes(b)
        if not windows:
            convert(b, True)
            first = source.read_bytes()
            convert(b, True)
            assert first == source.read_bytes()
            subprocess.run(['rustc', '-D', 'warnings', str(source), '-o', str(elf)], check=True)
        identity=dict(case=name, platform='windows' if windows else 'linux',
                      pe_sha256=hashlib.sha256(b).hexdigest())
        print('imported launching '+json.dumps(identity),flush=True)
        try:
            with open(root/'stdout','wb') as out, open(root/'stderr','wb') as err:
                p = subprocess.run([str(exe if windows else elf)], stdout=out, stderr=err, timeout=15)
        except subprocess.TimeoutExpired:
            print('imported timeout '+json.dumps(dict(identity,
                  stdout_hex=(root/'stdout').read_bytes().hex(),
                  stderr_hex=(root/'stderr').read_bytes().hex())),flush=True)
            raise
        actual = ((root/'stdout').read_bytes(), (root/'stderr').read_bytes(), p.returncode)
        assert actual == (b'' if skip else payload, b'', 0), (name, actual)
        print(f'imported {name}: stdout={actual[0].hex()} stderr={actual[1].hex()} exit={p.returncode}')
        if not windows and not skip:
            with open(os.devnull,'wb') as out:
                p = subprocess.run([str(elf)], stdout=out, stderr=subprocess.PIPE)
            assert p.returncode == 125 and b'unsupported output environment' in p.stderr
    if not windows:
        good = fixture(b'Hello')
        for end in range(len(good)):
            convert(good[:end], False)
        truncations = rejected
        # Literal offsets test descriptor/ILT/IAT/name/directory/permission failures.
        mutations = [(0x100,0x2fff),(0x104,39),(0x158,0x3054),(0x15c,4),
                     (0x600,0),(0x600,0x3050),(0x604,1),(0x608,1),(0x60c,0x3000),
                     (0x610,0x3054),(0x614,1),(0x640,0x80000001),(0x644,1),
                     (0x650,0x3084),(0x654,1),(0x1ec,0x40000040),(0x1d0,0x300),
                     (0x201,0),(0x201,65),(0x206,0x401fff),(0x206,0x40203e),
                     (0x206,0x403000),(0x206,0xffffffff),(0x20b,2),(0x211,0x403040), (0x600,0x30fc), (0x60c,0x30fa),
                     (0x610,0x3040), (0x640,0x30f8), (0x650,0x30f8)]
        for at,value in mutations:
            b=good.copy();put(b,at,value,4);convert(b,False)
        for at in [0x660,0x66a,0x680,0x682,0x688,0x400]:
            b=good.copy();b[at]=0xff;convert(b,False)
        # Untaken invalid buffer still rejects; unknown flags after call reject.
        b=fixture(b'Hello',True);put(b,0x20a,0x403000,4);convert(b,False)
        b=good.copy();b[0x221:0x226]=b'\xb8\x05\0\0\0';convert(b,False)
        # Missing caller cleanup and wrong FF register form.
        b=good.copy();b[0x215]=0xc3;convert(b,False)
        b=good.copy();b[0x210]=0xd0;convert(b,False)
        print(f'imported rejection checks: {len(good)} truncations, {rejected-truncations} adversarial cases')
