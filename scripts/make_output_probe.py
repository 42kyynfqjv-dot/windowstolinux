#!/usr/bin/env python3
"""Authored SUB-511 design probe; deliberately unsupported by production."""
from pathlib import Path
import sys
from make_pe32_fixture import build, put


def output_probe():
    data = bytearray(build('two_section_helper')) + bytearray(0x200)
    put(data, 0x86, 3, 2)
    put(data, 0x98 + 8, 0x400, 4)
    put(data, 0x98 + 56, 0x4000, 4)
    put(data, 0x98 + 104, 0x3000, 4)  # import directory
    put(data, 0x98 + 108, 40, 4)
    put(data, 0x98 + 192, 0x3050, 4)  # IAT directory
    put(data, 0x98 + 196, 8, 4)
    section = 0x1c8
    data[section:section+8] = b'.idata\0\0'
    for offset, value in [(8, 0x100), (12, 0x3000), (16, 0x200),
                          (20, 0x600), (36, 0xc0000040)]:
        put(data, section + offset, value, 4)
    data[0x200:0x300] = bytes(0x100)
    # cdecl: count, buffer, fd; call IAT; caller cleanup; verify return count.
    code = bytes.fromhex('6805000000 6800204000 6801000000 ff1550304000 '
                         '8d642404 8d642404 8d642404 3d05000000 7406 '
                         'b863000000 c3 b800000000 c3')
    data[0x200:0x200+len(code)] = code
    data[0x400:0x410] = b'Hello' + bytes(11)
    for offset, value in [(0x600, 0x3040), (0x60c, 0x3060),
                          (0x610, 0x3050), (0x640, 0x3080), (0x650, 0x3080)]:
        put(data, offset, value, 4)
    data[0x660:0x66b] = b'msvcrt.dll\0'
    data[0x682:0x689] = b'_write\0'
    assert len(data) == 0x800
    return bytes(data)


if __name__ == '__main__':
    Path(sys.argv[1]).write_bytes(output_probe())
