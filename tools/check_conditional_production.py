"""SUB-524 literal byte/IR/behavior regressions through production PE -> Rust -> ELF.
PE shell reuses the independently laid-out linker fixture; instruction layouts and
expected arithmetic below use no production/model decoder or arithmetic helper.
These native-only cases are separate from the unchanged MSVC Windows comparison.
"""
from pathlib import Path
import struct
import subprocess
import tempfile
from test_linker_intake import image

PREFIX = bytes.fromhex('56 6a05 6860204000 6a01 ff1500204000')
HELPER = bytes.fromhex('8b442408 ba01000000 8b4c2404 3bc8 0f4dc2 03c1 c3')
FORMS = [(0, 4, 'ScalarArgumentTwo'), (4, 5, 'EdxOne'), (9, 4, 'EcxArgumentOne'),
         (13, 2, 'CompareEcxEax'), (15, 3, 'SelectGe'), (18, 2, 'AddEcx')]
converter = Path('target/debug/w2l').resolve()


def fixture(program):
    assert len(program) <= 512
    b = image()
    b[0x400:0x400+len(program)] = program
    struct.pack_into('<I', b, 0x180, len(program))
    struct.pack_into('<HH', b, 0x808, 0x3004, 0x300c)
    return b


def compose(blocks):
    code = bytearray(PREFIX)
    labels = {}
    fixups = []
    for label, parts in blocks:
        labels[label] = len(code)
        for part in parts:
            if isinstance(part, tuple):
                branch = len(part) == 2
                fixups.append((len(code), part[0], branch))
                code.extend(b'\x75\x00' if branch else b'\xe8'+bytes(4))
            else:
                code.extend(bytes.fromhex(part) if isinstance(part, str) else part)
    for at, label, branch in fixups:
        displacement = labels[label] - at - (2 if branch else 5)
        assert displacement >= 0
        if branch:
            assert displacement <= 127
            code[at+1] = displacement
        else:
            struct.pack_into('<i', code, at+1, displacement)
    return code, labels


def push(n):
    return b'\x68'+struct.pack('<I', n)


def program(a=7, b=5, helper=HELPER, continuation='83c414 5e c3'):
    return compose([('entry', [push(b), push(a), ('leaf',), continuation]), ('leaf', [helper])])


native_count = rejection_count = 0
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    pe, rs = root/'input.exe', root/'native.rs'

    def convert(blob):
        pe.write_bytes(blob)
        return subprocess.run([str(converter), str(pe), str(rs)], capture_output=True, timeout=15)

    def execute(code, expected, ir=()):
        global native_count
        blob = fixture(code)
        p = convert(blob)
        assert p.returncode == 0, p.stderr
        source = rs.read_bytes()
        assert convert(blob).returncode == 0 and rs.read_bytes() == source
        assert b'iced_x86' not in source and b'include!' not in source
        for pc, op, next_pc in ir:
            assert f'{pc}=>(Op::{op},{next_pc}),'.encode() in source
        native = root/'native'
        subprocess.run(['rustc', '-D', 'warnings', str(rs), '-o', str(native)], check=True, capture_output=True, timeout=60)
        with (root/'out').open('wb') as out, (root/'err').open('wb') as err:
            result = subprocess.run([str(native)], stdout=out, stderr=err, timeout=15)
        assert (result.returncode, (root/'out').read_bytes(), (root/'err').read_bytes()) == (expected, b'Hello', b'')
        native_count += 1

    def reject(code, message=None):
        global rejection_count
        rs.write_bytes(b'preserve')
        p = convert(fixture(code))
        assert p.returncode == 1 and rs.read_bytes() == b'preserve', (code.hex(), p.stderr)
        if message:
            assert message in p.stderr.decode(), p.stderr
        rejection_count += 1

    # Both real helper selections; signed wrap result -1 is checked before entry
    # exit normalization, because Linux cannot represent the full Windows status.
    for a, b, expected in [(7, 5, 8), (3, 4, 7), (0, 0, 1), (0xffffffff, 1, 0),
                           (0x80000000, 0x7fffffff, -1)]:
        suffix = bytes.fromhex('83c414 83f8') + bytes([expected & 255]) + bytes.fromhex('7504 33c0 5e c3 b863000000 5e c3')
        code, labels = program(a, b, continuation=suffix)
        start = 0x1000 + labels['leaf']
        execute(code, 0, [(start+offset, op, start+offset+size) for offset, size, op in FORMS])

    # Literal signed comparison outcomes, including subtraction overflow. MOV
    # normalizes the observation while preserving the flags consumed by CMOV.
    for a, b, expected in [(7, 5, 1), (3, 4, 0), (0, 0, 1),
                           (0x80000000, 0x7fffffff, 0), (0x7fffffff, 0x80000000, 1),
                           (0xffffffff, 0, 0), (0, 0xffffffff, 1)]:
        helper = bytes.fromhex('8b442408 ba01000000 8b4c2404 3bc8 b800000000 0f4dc2 c3')
        execute(program(a, b, helper)[0], expected)

    # SF==OF after ADD: positive overflow, negative overflow and wrap to zero.
    for a, b, expected in [(0x7fffffff, 1, 1), (0x80000000, 0x80000000, 0), (0xffffffff, 1, 1)]:
        helper = bytes.fromhex('8b442408 ba01000000 8b4c2404 03c1 b800000000 0f4dc2 c3')
        execute(program(a, b, helper)[0], expected)

    # The same helper runs twice with distinct arguments and continuations.
    code, _ = compose([
        ('entry', ['6a05 6a07', ('leaf',), '83c414 83f808', ('bad', 'jnz'),
                   '6a04 6a03', ('leaf',), '83c408 83f807', ('bad', 'jnz'), '33c0 5e c3']),
        ('bad', ['b863000000 5e c3']), ('leaf', [HELPER])])
    execute(code, 0)
    # New volatile values survive actual internal RET, then drive caller ADD.
    code, _ = program(7, 5, continuation='83c414 03c1 5e c3')
    execute(code, 15)

    # A nested callee supplies ECX/EDX; neither CALL nor RET restores old values.
    code, _ = compose([
        ('entry', ['6a05 6a07', ('outer',), '83c414 5e c3']),
        ('outer', ['6a04 6a03', ('leaf',), '83c408 03c1 c3']),
        ('leaf', [HELPER])])
    execute(code, 10)

    # Exact forms only: each truncation ends the executable mapping inside that
    # instruction; each prefix/neighbor changes the literal accepted encoding.
    for offset, size, _ in FORMS:
        for prefix in [b'\x66', b'\x67', b'\xf2', b'\xf3', b'\x2e']:
            reject(program(helper=HELPER[:offset]+prefix+HELPER[offset:])[0])
        for end in range(1, size):
            reject(program(helper=HELPER[:offset+end])[0])
    for offset, value in [(2, 0x25), (3, 12), (4, 0xb9), (5, 2), (6, 1),
                          (10, 0x54), (12, 8), (13, 0x39), (14, 0xc1),
                          (16, 0x4c), (17, 0xc1), (17, 0x02), (19, 0xc2)]:
        altered = bytearray(HELPER)
        altered[offset] = value
        reject(program(helper=altered)[0])

    # CMOV's false path still requires a known EDX source. Cleanup's unknown
    # flags cannot be repaired by MOV; pointers never become scalar operands.
    for helper, message in [
        ('8b442408 8b4c2404 3bc8 0f4dc2 c3', 'scalar required'),
        ('8b442408 ba01000000 0f4dc2 c3', 'unknown conditional flags'),
        ('8b442408 03c1 c3', 'scalar required'),
        ('8b442408 3bc8 c3', 'scalar required'),
        ('56 8b4c2404 c3', 'argument return boundary'),
    ]:
        reject(program(3, 4, bytes.fromhex(helper))[0], message)
    for helper in ['8b4c2404 c3', '8b442408 c3']:
        # No caller arguments after cleaning the output arguments.
        code, _ = compose([('entry', ['6a00 6a00 83c414', ('leaf',), '5e c3']), ('leaf', [helper])])
        reject(code, 'argument ownership')
    # Original output pointer is argument2; reject new scalar load of it.
    code, _ = compose([('entry', [('leaf',), '5e c3']), ('leaf', ['8b442408 c3'])])
    reject(code, 'scalar required')
    # Unknown flag use on the continuation and on a statically untaken branch.
    reject(program(continuation='83c414 b800000000 0f4dc2 5e c3')[0], 'unknown conditional flags')
    bad_leaf = bytes.fromhex('8b442408 ba01000000 8b4c2404 3bc8 7504 0f4dc2 c3 56 8b4c2404 c3')
    reject(program(0, 0, bad_leaf)[0], 'argument return boundary')
    # The taken path skips EDX initialization and joins a valid fallthrough.
    # Even when the real equal-input run falls through, that unknown state rejects.
    joined = bytes.fromhex('8b442408 8b4c2404 3bc8 7505 ba01000000 0f4dc2 c3')
    reject(program(0, 0, joined)[0], 'scalar required')
    # A second output through the SAME import call is impossible without backward
    # transfer; instead put the only relocated output after the helper. Its summary
    # must invalidate both known volatile registers before scalar use.
    for tail in ['03c1', '83f805 0f4dc2']:
        before = bytes.fromhex('56 6a05 6a07 e800000000 83c408')
        after = bytes.fromhex('6a05 6860204000 6a01 ff1500204000 '+tail+' 5e c3')
        code = bytearray(before+after+HELPER)
        struct.pack_into('<i', code, 6, len(before)+len(after)-10)
        blob = fixture(code)
        struct.pack_into('<HH', blob, 0x808, 0x3000+len(before)+3, 0x3000+len(before)+11)
        rs.write_bytes(b'preserve')
        p = convert(blob)
        assert p.returncode == 1 and b'scalar required' in p.stderr and rs.read_bytes() == b'preserve', p.stderr
        rejection_count += 1

print(f'conditional production: {native_count} deterministic native-only cases, {rejection_count} production CLI rejections; separate from unchanged compiler Windows/Linux evidence')
