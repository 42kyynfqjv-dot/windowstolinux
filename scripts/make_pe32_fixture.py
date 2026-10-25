"""Build an independently authored, import-free PE32 entry-return fixture.

The entry computes 7 + 5 in EAX and returns. This is only a narrow process
exit-status experiment, not an application compatibility corpus.
"""

import sys
from pathlib import Path


def put(data: bytearray, offset: int, value: int, width: int) -> None:
    data[offset : offset + width] = value.to_bytes(width, "little")


def build() -> bytes:
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    put(data, 0x3C, 0x80, 4)
    data[0x80:0x84] = b"PE\0\0"

    coff = 0x84
    put(data, coff + 0, 0x14C, 2)  # x86
    put(data, coff + 2, 1, 2)  # one section
    put(data, coff + 16, 0xE0, 2)  # PE32 optional header size
    put(data, coff + 18, 0x0102, 2)  # executable, 32-bit

    optional = 0x98
    put(data, optional + 0, 0x10B, 2)  # PE32
    put(data, optional + 4, 0x200, 4)  # SizeOfCode
    put(data, optional + 16, 0x1000, 4)  # AddressOfEntryPoint
    put(data, optional + 20, 0x1000, 4)  # BaseOfCode
    put(data, optional + 24, 0x1000, 4)  # BaseOfData
    put(data, optional + 28, 0x400000, 4)  # ImageBase
    put(data, optional + 32, 0x1000, 4)  # SectionAlignment
    put(data, optional + 36, 0x200, 4)  # FileAlignment
    put(data, optional + 40, 4, 2)  # MajorOperatingSystemVersion
    put(data, optional + 48, 4, 2)  # MajorSubsystemVersion
    put(data, optional + 56, 0x2000, 4)  # SizeOfImage
    put(data, optional + 60, 0x200, 4)  # SizeOfHeaders
    put(data, optional + 68, 3, 2)  # console subsystem
    put(data, optional + 72, 0x100000, 4)  # stack reserve
    put(data, optional + 76, 0x1000, 4)  # stack commit
    put(data, optional + 80, 0x100000, 4)  # heap reserve
    put(data, optional + 84, 0x1000, 4)  # heap commit
    put(data, optional + 92, 16, 4)  # NumberOfRvaAndSizes

    section = 0x178
    data[section : section + 5] = b".text"
    put(data, section + 8, 0x100, 4)  # virtual size
    put(data, section + 12, 0x1000, 4)  # virtual address
    put(data, section + 16, 0x200, 4)  # raw size
    put(data, section + 20, 0x200, 4)  # raw offset
    put(data, section + 36, 0x60000020, 4)  # code, execute, read

    data[0x200:0x20B] = bytes([0xB8, 7, 0, 0, 0, 0x05, 5, 0, 0, 0, 0xC3])
    return bytes(data)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: make_pe32_fixture.py OUTPUT.exe")
    Path(sys.argv[1]).write_bytes(build())
