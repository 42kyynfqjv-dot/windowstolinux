"""Authored output fixture byte construction, shared without executing tests."""
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
