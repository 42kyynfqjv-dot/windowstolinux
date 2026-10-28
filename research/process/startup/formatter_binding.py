"""Bind retained integer-formatter bytes, data and exception edges to one PE.

This is research extraction, never a converter certificate or application-ID
dispatch. Linked-library extents are measured instruction/data boundaries, not
COFF function symbols: only the authored Main/printf caller has object linkage.
The Rust proofs must decode every admitted instruction and justify unreachable
paths independently. In particular, the C++ record below is not an EH4 table.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from coff_binding import bind_function, cut, pe_sections, u32
from frame_binding import instructions
from reported_binding import extract as extract_reported


def sha(data):
    return hashlib.sha256(data).hexdigest()


# Address selection is a recorded measurement of the unchanged artifact. It is
# intentionally separate from production instruction/effect admission.
CODE = [
    ('formatter_entry', 0x40643e, 0x4064e2),
    ('locked_formatter', 0x40465c, 0x4046a8),
    ('locked_cleanup', 0x4046a8, 0x4046b7),
    ('formatter_driver', 0x4052ba, 0x405356),
    ('formatter_state_constructor', 0x405175, 0x4051dc),
    ('formatter_context_constructor', 0x4051e0, 0x40523d),
    ('formatter_context_destructor', 0x405240, 0x40527c),
    ('formatter_buffer_destructor', 0x40527c, 0x405296),
    ('format_parser', 0x405584, 0x405809),
    ('format_state', 0x4053c0, 0x4053fb),
    ('format_modifier', 0x40582c, 0x405985),
    ('integer_dispatch', 0x405985, 0x405d77),
    ('integer_magnitude', 0x404b72, 0x404cff),
    ('decimal32', 0x404eee, 0x404f6d),
    ('buffer_capacity', 0x4046b7, 0x4046cf),
    ('length_lookup', 0x405d7c, 0x405dad),
    ('formatter_validate', 0x406256, 0x40628e),
    ('formatter_encoding', 0x40628e, 0x406315),
    ('formatter_fileno', 0x409d6b, 0x409d92),
    ('formatter_classify', 0x40641c, 0x40643e),
    ('integer_cxx_handler', 0x414aaf, 0x414ad6),
    ('cxx_dispatch_wrapper', 0x403002, 0x403038),
    ('integer_unwind_action', 0x4026fc, 0x402701),
    ('termination_path', 0x40770c, 0x407748),
]
DATA = [
    ('parser_jumps', 0x40580c, 32),
    ('state_table', 0x415dd8, 256),
    ('length_jumps', 0x405db0, 20),
    ('length_classes', 0x405dc4, 12),
    ('integer_cxx_unwind_map', 0x41b3d0, 8),
    ('integer_cxx_metadata', 0x41b3d8, 36),
    ('locked_eh4_table', 0x41b400, 28),
]
PADDING = [
    ('parser_padding', 0x405809, bytes.fromhex('0f1f00')),
    ('integer_padding', 0x405d77, b'\xcc'*5),
    ('length_padding', 0x405dad, bytes.fromhex('0f1f00')),
]


def mapped(image, va, size, executable=False, readonly=False):
    base, sections = pe_sections(image)
    if type(va) is not int or type(size) is not int or not 0 < size <= 16384 or not base <= va < va+size <= 2**32:
        raise ValueError('formatter evidence range/overflow/budget')
    matches = []
    for section in sections:
        begin = base+section['rva']
        if begin <= va and va+size <= begin+min(section['size'], section['virtual']):
            if executable and not section['flags'] & 0x20000000:
                raise ValueError('formatter code is not executable')
            if readonly and section['flags'] & 0x80000000:
                raise ValueError('formatter table is writable')
            matches.append(cut(image, section['start']+va-begin, size))
    if len(matches) != 1:
        raise ValueError('formatter evidence range missing or ambiguous')
    return matches[0]


def operand(image, site, prefix, size=4):
    """Bind a measured address operand to its exact original instruction form."""
    raw = mapped(image, site, len(prefix)+size, executable=True)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f'formatter address operand changed at {site:#x}')
    return int.from_bytes(raw[len(prefix):], 'little')


def relative(image, site, opcode):
    raw = mapped(image, site, 5, executable=True)
    if raw[0] != opcode:
        raise ValueError(f'formatter relative edge changed at {site:#x}')
    target = site+5+int.from_bytes(raw[1:], 'little', signed=True)
    if not 0 <= target < 2**32:
        raise ValueError('formatter relative edge overflow')
    return target


def code_rows(image, index, begin, end):
    base, _ = pe_sections(image)
    rows = []
    pc = begin
    while pc < end:
        # Dumpbin's linear sweep interprets the preceding jump table as code and
        # makes one false row span 0x40582b..0x405831. The actual original CALL
        # targets 0x40582c. Retain these two independently readable x86 encodings,
        # then rejoin the byte-checked listing; production must decode afresh.
        repair = {0x40582c: '8a412d', 0x40582f: '3c46'}.get(pc)
        if repair is not None:
            raw = bytes.fromhex(repair)
            source = 'explicit entry decode after embedded jump table'
        else:
            row = index.get(pc-base)
            if row is None:
                raise ValueError(f'formatter instruction boundary missing at {pc:#x}')
            raw = bytes.fromhex(row['code_hex'])
            source = 'original dumpbin listing, byte checked against PE'
        if not raw or pc+len(raw) > end or mapped(image, pc, len(raw), executable=True) != raw:
            raise ValueError(f'formatter instruction range disagreement at {pc:#x}')
        rows.append(dict(va=pc, size=len(raw), code_hex=raw.hex(), boundary_source=source))
        pc += len(raw)
    return rows


def edges(rows):
    """Inventory all CALL and direct/indirect branch encodings in retained rows.

    This records dependencies, not reachability or semantics. No dependency is
    called harmless because a frozen input does not visit it.
    """
    result = []
    for row in rows:
        pc = row['va']
        raw = bytes.fromhex(row['code_hex'])
        if len(raw) == 5 and raw[0] in (0xe8, 0xe9):
            result.append(dict(site=pc, kind='call' if raw[0] == 0xe8 else 'jump',
                               target=(pc+5+int.from_bytes(raw[1:], 'little', signed=True)) & 0xffffffff))
        elif raw[0] == 0xff and len(raw) >= 2 and (raw[1] >> 3) & 7 in (2, 4):
            result.append(dict(site=pc, kind='indirect_call' if (raw[1] >> 3) & 7 == 2 else 'indirect_jump',
                               encoding=raw.hex(), effects_proven=False))
        elif len(raw) == 2 and (0x70 <= raw[0] <= 0x7f or raw[0] == 0xeb):
            result.append(dict(site=pc, kind='branch' if raw[0] != 0xeb else 'jump',
                               target=(pc+2+int.from_bytes(raw[1:], 'little', signed=True)) & 0xffffffff))
        elif len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
            result.append(dict(site=pc, kind='branch',
                               target=(pc+6+int.from_bytes(raw[2:], 'little', signed=True)) & 0xffffffff))
    return result


def extract(original, output):
    original, output = Path(original), Path(output)
    image = (original/'unwind.exe').read_bytes()
    obj = (original/'unwind.obj').read_bytes()
    source = (original/'unwind_probe.c').read_bytes()
    report = json.loads((original/'report.json').read_text())
    if report['pe_sha256'] != sha(image) or report['source_sha256'] != sha(source):
        raise ValueError('retained formatter source/PE does not match original build report')
    repository_source = Path(__file__).with_name('unwind_probe.c').read_bytes()
    if source.replace(b'\r\n', b'\n') != repository_source.replace(b'\r\n', b'\n'):
        raise ValueError('retained formatter authored source differs from reviewed source')
    listing = (original/'disasm.txt').read_bytes()
    index = instructions(listing.decode(), image)
    base, _ = pe_sections(image)
    regions = []
    intervals = []
    for name, start, end in CODE:
        raw = mapped(image, start, end-start, executable=True)
        rows = code_rows(image, index, start, end)
        regions.append(dict(name=name, va=start, size=len(raw), file=name+'.bin', sha256=sha(raw),
                            kind='code', instructions=rows, edges=edges(rows), effects_proven=False))
        intervals.append((start, end, name))
    for name, start, size in DATA:
        raw = mapped(image, start, size, readonly=True)
        regions.append(dict(name=name, va=start, size=size, file=name+'.bin', sha256=sha(raw), kind='data', effects_proven=False))
        intervals.append((start, start+size, name))
    for name, start, expected in PADDING:
        if mapped(image, start, len(expected), executable=True) != expected:
            raise ValueError('formatter padding changed: '+name)
        regions.append(dict(name=name, va=start, size=len(expected), file=name+'.bin', sha256=sha(expected), kind='padding', effects_proven=False))
        intervals.append((start, start+len(expected), name))
    for left, right in zip(sorted(intervals), sorted(intervals)[1:]):
        if left[1] > right[0]:
            raise ValueError('formatter code/data/padding alias')
    by_name = {r['name']: r for r in regions}

    # Each table's address comes from the original indexed-read/jump operand.
    bindings = [
        (0x405634, bytes.fromhex('ff2485'), 'parser_jumps', 0),
        (0x4053d8, bytes.fromhex('8a0445'), 'state_table', 1),
        (0x4053f0, bytes.fromhex('8a0445'), 'state_table', 0),
        (0x405d89, bytes.fromhex('0fb680'), 'length_classes', 0),
        (0x405d90, bytes.fromhex('ff2485'), 'length_jumps', 0),
    ]
    for site, prefix, name, delta in bindings:
        if operand(image, site, prefix) != by_name[name]['va']+delta:
            raise ValueError('formatter original table operand mismatch: '+name)
    for name, code_name in [('parser_jumps', 'format_parser'), ('length_jumps', 'length_lookup')]:
        table = by_name[name]
        raw = mapped(image, table['va'], table['size'], readonly=True)
        targets = list(struct.unpack('<'+'I'*(len(raw)//4), raw))
        boundaries = {row['va'] for row in by_name[code_name]['instructions']}
        if any(target not in boundaries for target in targets):
            raise ValueError('formatter jump table target is not an original code boundary')
        table['targets'] = targets
    classes = list(mapped(image, by_name['length_classes']['va'], 12, readonly=True))
    if any(value >= len(by_name['length_jumps']['targets']) for value in classes):
        raise ValueError('formatter length class exceeds jump table')
    by_name['length_classes']['values'] = classes

    expected_edges = [
        (0x40644d, 0x4051e0), (0x4064d8, 0x405240),
        (0x4064ce, 0x40465c), (0x40467e, 0x4052ba),
        (0x405314, 0x405175), (0x405330, 0x40527c),
        (0x405323, 0x405584), (0x40561c, 0x4053c0),
        (0x40576d, 0x40582c), (0x405776, 0x405985),
        (0x405a5d, 0x404b72), (0x404b82, 0x405d7c),
        (0x404cce, 0x404eee), (0x404f07, 0x4046b7),
        (0x40559a, 0x406256), (0x406284, 0x40628e),
        (0x4062a4, 0x409d6b), (0x405664, 0x40641c),
    ]
    for site, target in expected_edges:
        if relative(image, site, 0xe8) != target:
            raise ValueError('formatter original linked call graph changed')

    # Raw FuncInfo/map words are retained, not reinterpreted as EH4 or proof of
    # the common C++ runtime dispatcher. The action and its terminal dependency
    # are real original code, including the possible PTD termination callback.
    if operand(image, 0x40598c, b'\x68') != by_name['integer_cxx_handler']['va']:
        raise ValueError('integer C++ handler registration changed')
    metadata_va = operand(image, 0x414acc, b'\xb8')
    if metadata_va != by_name['integer_cxx_metadata']['va']:
        raise ValueError('integer C++ metadata identity changed')
    words = list(struct.unpack('<9I', mapped(image, metadata_va, 36, readonly=True)))
    if words[0] != 0x19930522 or words[1] != 1 or words[2] != by_name['integer_cxx_unwind_map']['va']:
        raise ValueError('integer C++ metadata layout/count/map changed')
    unwind = list(struct.unpack('<2I', mapped(image, words[2], 8, readonly=True)))
    if unwind != [0xffffffff, by_name['integer_unwind_action']['va']]:
        raise ValueError('integer C++ state-zero unwind action changed')
    termination = relative(image, unwind[1], 0xe9)
    if termination != by_name['termination_path']['va'] or relative(image, 0x414ad1, 0xe9) != 0x403002:
        raise ValueError('integer C++ original unwind/dispatcher edge changed')
    if relative(image, 0x403023, 0xe8) != 0x403e78:
        raise ValueError('integer common C++ dispatcher edge changed')
    if operand(image, 0x40465e, b'\x68') != by_name['locked_eh4_table']['va']:
        raise ValueError('locked wrapper EH4 metadata changed')
    locked_words = list(struct.unpack('<7I', mapped(image, 0x41b400, 28, readonly=True)))
    if locked_words[4:] != [0xfffffffe, 0, by_name['locked_cleanup']['va']]:
        raise ValueError('locked wrapper original cleanup edge changed')

    output.mkdir(parents=True, exist_ok=True)
    caller_dir = output/'caller-provenance'
    caller_dir.mkdir(exist_ok=True)
    caller = extract_reported(original, caller_dir)
    if caller['formatter_va'] != by_name['formatter_entry']['va']:
        raise ValueError('original COFF printf call does not identify measured formatter')
    for region in regions:
        (output/region['file']).write_bytes(mapped(image, region['va'], region['size']))
    result = dict(
        schema=1, kind='original formatter code/data and C++ edge extraction; not execution eligibility',
        image_base=base, pe_sha256=sha(image), object_sha256=sha(obj), source_sha256=sha(source),
        source_lf_sha256=sha(source.replace(b'\r\n', b'\n')), disassembly_sha256=sha(listing),
        compiler_version_sha256=sha((original/'compiler-version.txt').read_bytes()),
        original_build=dict(command=report['command'], compiler_sha256=report['compiler_sha256'],
                            vc_tools_version=report['vc_tools_version'], windows_sdk_version=report['windows_sdk_version']),
        caller_object_bindings=[bind_function(obj, image, symbol) for symbol in ['_main', '_printf']],
        caller_evidence='caller-provenance/reported-binding.json',
        regions=regions, original_call_edges=[dict(site=site, target=target) for site, target in expected_edges],
        table_operands=[dict(site=site, table=name, byte_offset=delta) for site, _, name, delta in bindings],
        modifier_entry_boundary_note='Actual CALL targets 0x40582c after 32-byte table; dumpbin linear row at 0x40582b overlaps it. Raw MOV AL,[ECX+0x2d];CMP AL,0x46 boundaries independently retained.',
        formatter_abi=dict(stack_words=['options_low', 'options_high', 'FILE_pointer', 'format_pointer', 'locale_pointer', 'varargs_pointer'],
                           convention='x86 cdecl at formatter_entry; ECX this-pointer and RET n at measured member helpers',
                           argument_word_bytes=4, integer_width=32, long_width=32,
                           obligations='Typed initialized argument ownership; exact partial AL/flags and original caller cleanup remain production proof obligations.'),
        cxx_record=dict(record_ebp_offset=-12, state_ebp_offset=-4, handler_va=0x414aaf,
                        cookie_ebp_offsets=[-16, -64], metadata_va=metadata_va, metadata_words=words,
                        unwind_map_va=words[2], unwind_map_words=unwind, state_zero_store_va=0x405c02,
                        action_va=unwind[1], action_target_va=termination, common_dispatch_target_va=0x403e78,
                        classification='Original C++ registration/FuncInfo, NOT EH4; unproved general dispatcher and termination callback effects'),
        lock_cleanup=dict(eh4_table_va=0x41b400, raw_words=locked_words, normal_cleanup_entry=0x4046ab,
                          unwind_cleanup_entry=0x4046a8, unlock_target=0x404648,
                          note='Distinct from integer C++ state-zero termination action.'),
        unclosed_effects=[
            'Common C++ dispatcher 0x403e78 and exceptional state-zero action are not certified by extraction.',
            'Termination path 0x40770c reads a PTD callback at +0x0c, may call it, then calls 0x4077ff; no harmless-cleanup or normal-return substitution.',
            'Locale/context constructor/destructor, FILE lock/unlock and temporary buffering setup/teardown require original effect proofs.',
            'Width, precision, floating, string, wide and 64-bit paths must be proved unreachable for the selected grammar or fully implemented.',
            'Source/object/caller linkage does not provide proprietary CRT source or closed startup semantics.',
        ],
        primary_contracts=[
            'https://learn.microsoft.com/en-us/cpp/cpp/thiscall?view=msvc-170',
            'https://learn.microsoft.com/en-us/cpp/c-runtime-library/cxxframehandler?view=msvc-170',
            'https://learn.microsoft.com/en-us/cpp/c-runtime-library/internal-crt-globals-and-functions?view=msvc-170',
            'https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/terminate-crt?view=msvc-170',
            'https://learn.microsoft.com/en-us/cpp/c-runtime-library/format-specification-syntax-printf-and-wprintf-functions?view=msvc-170',
        ],
        emission_allowed=False, whole_pe_translation_pairs=0,
    )
    (output/'formatter.manifest').write_text(''.join(f"region {r['name']} {r['va']} {r['file']}\n" for r in regions if r['kind'] != 'padding'))
    (output/'formatter-binding.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = extract(args.original, args.output)
    print(json.dumps(dict(pe_sha256=result['pe_sha256'], regions=len(result['regions']), emission_allowed=False)))
