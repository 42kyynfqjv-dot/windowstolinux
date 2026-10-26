"""Build independently authored, import-free PE32 entry-return fixtures.

These are narrow process exit-status experiments, not an application corpus.
"""

import sys
from pathlib import Path


def put(data: bytearray, offset: int, value: int, width: int) -> None:
    data[offset : offset + width] = value.to_bytes(width, "little")


def mov_eax(value: int) -> bytes:
    return bytes([0xB8]) + value.to_bytes(4, "little")


def add_eax(value: int) -> bytes:
    return bytes([0x05]) + value.to_bytes(4, "little")


CASES = {
    "sum12": mov_eax(7) + add_eax(5) + b"\xC3",
    "wrap2": mov_eax(0xFFFFFFFF) + add_eax(3) + b"\xC3",
    "xor9": b"\x31\xC0" + add_eax(9) + b"\xC3",
    "zero": mov_eax(0) + b"\xC3",
    "max255": mov_eax(255) + b"\xC3",
    "out_of_range": mov_eax(256) + b"\xC3",
}


def branch_case(prefix: bytes, opcode: int) -> bytes:
    return prefix + bytes([opcode, 6]) + mov_eax(11) + b"\xC3" + mov_eax(22) + b"\xC3"


for name, prefix, opcode in [
    ("jc_taken", mov_eax(0xFFFFFFFF) + add_eax(1), 0x72),
    ("jc_clear", mov_eax(1) + add_eax(1), 0x72),
    ("jnc_taken", mov_eax(1) + add_eax(1), 0x73),
    ("jnc_clear", mov_eax(0xFFFFFFFF) + add_eax(1), 0x73),
    ("jz_taken", mov_eax(0xFFFFFFFF) + add_eax(1), 0x74),
    ("jz_clear", mov_eax(1) + add_eax(1), 0x74),
    ("jnz_taken", mov_eax(1) + add_eax(1), 0x75),
    ("jnz_clear", mov_eax(0xFFFFFFFF) + add_eax(1), 0x75),
    ("mov_flags", b"\x31\xC0" + mov_eax(7), 0x74),
    ("xor_carry", b"\x31\xC0", 0x72),
]:
    CASES[name] = branch_case(prefix, opcode)

CASES["join_taken"] = b"\x31\xc0\x74\x05" + mov_eax(11) + add_eax(1) + b"\xc3"
CASES["join_fallthrough"] = mov_eax(1) + add_eax(0) + b"\x74\x05" + mov_eax(11) + add_eax(1) + b"\xc3"
CASES["same_successor"] = b"\x31\xc0\x74\x00" + add_eax(3) + b"\xc3"
CASES["entry_offset"] = CASES["sum12"]


def cmp_eax(value: int) -> bytes:
    return b"\x3d" + value.to_bytes(4, "little")


for name, prefix, opcode in [
    ("cmp_min_max_jl", mov_eax(0x80000000) + cmp_eax(0x7fffffff), 0x7c),
    ("cmp_max_min_jl", mov_eax(0x7fffffff) + cmp_eax(0x80000000), 0x7c),
    ("cmp_equal_jge", mov_eax(7) + cmp_eax(7), 0x7d),
    ("cmp_less_jge", mov_eax(0xffffffff) + cmp_eax(0), 0x7d),
    ("cmp_borrow", mov_eax(0) + cmp_eax(1), 0x72),
    ("cmp_no_borrow", mov_eax(0xffffffff) + cmp_eax(0), 0x73),
    ("cmp_zero", mov_eax(7) + cmp_eax(7), 0x74),
    ("cmp_nonzero", mov_eax(7) + cmp_eax(8), 0x75),
    ("cmp_mov_flags", mov_eax(0x80000000) + cmp_eax(0x7fffffff) + mov_eax(7), 0x7c),
    ("add_signed_overflow", mov_eax(0x7fffffff) + add_eax(1), 0x7c),
    ("add_negative_overflow", mov_eax(0x80000000) + add_eax(0xffffffff), 0x7c),
    ("xor_signed_reset", mov_eax(0x80000000) + add_eax(0) + b"\x31\xc0", 0x7d),
]:
    CASES[name] = branch_case(prefix, opcode)
CASES["cmp_preserve_eax"] = mov_eax(42) + cmp_eax(100) + b"\xc3"

for name, a, b in [("signed_join_taken", 0x80000000, 0x7fffffff), ("signed_join_fallthrough", 0x7fffffff, 0x80000000)]:
    CASES[name] = mov_eax(a) + cmp_eax(b) + b"\x7c\x05" + mov_eax(11) + cmp_eax(0) + b"\x7c\x06" + mov_eax(11) + b"\xc3" + mov_eax(22) + b"\xc3"


# Independently authored helper programs; rel32 offsets are literal and reviewed.
CASES["call_helper"] = b"\xe8\x06\x00\x00\x00" + add_eax(5) + b"\xc3" + mov_eax(7) + b"\xc3"
CASES["call_nested"] = b"\xe8\x06\x00\x00\x00" + add_eax(5) + b"\xc3\xe8\x01\x00\x00\x00\xc3" + mov_eax(7) + b"\xc3"
CASES["call_shared"] = mov_eax(1) + b"\xe8\x0b\x00\x00\x00\xe8\x06\x00\x00\x00" + add_eax(3) + b"\xc3" + add_eax(2) + b"\xc3"
CASES["call_flags_preserved"] = b"\x31\xc0\xe8\x0e\x00\x00\x00\x74\x06" + mov_eax(11) + b"\xc3" + mov_eax(22) + b"\xc3" + mov_eax(7) + b"\xc3"
CASES["call_flags_changed"] = mov_eax(0) + b"\xe8\x0e\x00\x00\x00\x74\x06" + mov_eax(11) + b"\xc3" + mov_eax(22) + b"\xc3" + add_eax(1) + b"\xc3"
CASES["call_unknown_then_init"] = b"\xe8\x06\x00\x00\x00" + mov_eax(42) + b"\xc3\xc3"
CASES["call_wide_internal"] = b"\xe8\x06\x00\x00\x00" + add_eax(0xffffff00) + b"\xc3" + mov_eax(256) + b"\xc3"


# Shared callee takes a different conditional return path on its second call.
CASES["call_shared_branch"] = mov_eax(0) + b"\xe8\x11\x00\x00\x00" + add_eax(0) + b"\xe8\x07\x00\x00\x00" + add_eax(3) + b"\xc3\x90" + cmp_eax(0) + b"\x74\x06" + mov_eax(2) + b"\xc3" + mov_eax(1) + b"\xc3"


# SUB-508 single-word caller-cleanup fixtures. Literal displacements are reviewed
# independently of the production lifter. PUSH/LOAD/LEA preserve flags.
def push_data(value: int) -> bytes:
    return b"\x68" + value.to_bytes(4, "little")


LOAD_ARGUMENT = b"\x8b\x44\x24\x04"
DROP_DATA = b"\x8d\x64\x24\x04"
ARGUMENT_PLUS_FIVE = LOAD_ARGUMENT + add_eax(5) + b"\xc3"
CASES["stack_argument"] = push_data(7) + b"\xe8\x05\x00\x00\x00" + DROP_DATA + b"\xc3" + ARGUMENT_PLUS_FIVE
CASES["stack_shared"] = push_data(7) + b"\xe8\x20\x00\x00\x00" + DROP_DATA + cmp_eax(12) + b"\x74\x06" + mov_eax(99) + b"\xc3" + push_data(9) + b"\xe8\x05\x00\x00\x00" + DROP_DATA + b"\xc3" + ARGUMENT_PLUS_FIVE
CASES["stack_nested"] = push_data(7) + b"\xe8\x05\x00\x00\x00" + DROP_DATA + b"\xc3" + push_data(11) + b"\xe8\x1b\x00\x00\x00" + DROP_DATA + cmp_eax(16) + b"\x74\x06" + mov_eax(99) + b"\xc3" + ARGUMENT_PLUS_FIVE + ARGUMENT_PLUS_FIVE
# Same helper takes both branch paths across two invocations; local data is
# balanced before the join so [ESP+4] again denotes that invocation's argument.
CASES["stack_shared_join"] = CASES["stack_shared"][:-len(ARGUMENT_PLUS_FIVE)] + LOAD_ARGUMENT + cmp_eax(7) + b"\x74\x09" + push_data(99) + DROP_DATA + ARGUMENT_PLUS_FIVE
for name, prefix, opcode in [
    ("stack_flags_zero", b"\x31\xc0", 0x74),
    ("stack_flags_carry", mov_eax(0xffffffff) + add_eax(1), 0x72),
    ("stack_flags_overflow", mov_eax(0x7fffffff) + add_eax(1), 0x7c),
    ("stack_flags_negative_overflow", mov_eax(0x80000000) + add_eax(0xffffffff), 0x7c),
    ("stack_flags_negative", mov_eax(0x80000000) + add_eax(0), 0x7c),
    ("stack_flags_clear", mov_eax(1) + add_eax(1), 0x7c),
]:
    CASES[name] = branch_case(prefix + push_data(7) + b"\xe8\x12\x00\x00\x00" + DROP_DATA, opcode) + LOAD_ARGUMENT + b"\xc3"


CASES["two_section_helper"] = CASES["stack_argument"]

def build(case: str) -> bytes:
    if case not in CASES:
        raise ValueError(f"unknown fixture case: {case}")
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

    code = CASES[case]
    entry_offset = 8 if case == "entry_offset" else 0
    put(data, optional + 16, 0x1000 + entry_offset, 4)
    data[0x200 : 0x200 + entry_offset] = b"\x90" * entry_offset
    start = 0x200 + entry_offset
    data[start : start + len(code)] = code
    if case == "two_section_helper":
        data.extend(bytes(0x200))
        put(data, coff + 2, 2, 2)
        put(data, optional + 8, 0x200, 4)
        put(data, optional + 24, 0x2000, 4)
        put(data, optional + 56, 0x3000, 4)
        second = section + 40
        data[second:second+8] = b".rdata\0\0"
        put(data, second + 8, 16, 4)
        put(data, second + 12, 0x2000, 4)
        put(data, second + 16, 0x200, 4)
        put(data, second + 20, 0x400, 4)
        put(data, second + 36, 0x40000040, 4)
        data[0x400:0x410] = b"authored data!\0\0"
    return bytes(data)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: make_pe32_fixture.py CASE OUTPUT.exe")
    Path(sys.argv[2]).write_bytes(build(sys.argv[1]))
