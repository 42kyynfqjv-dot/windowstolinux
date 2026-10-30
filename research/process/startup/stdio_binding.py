"""Retain original CRT instruction/data provenance for a bounded component.

Addresses below select this research measurement, never converter admission.
The compiler consumes bytes/roles and must independently validate their effects.
An extracted region, hash match, or successful decode is not a proof token.
"""
import argparse
import hashlib
import json
from pathlib import Path

from coff_binding import cut, pe_sections, import_at_iat, u32
from frame_binding import instructions


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def mapped(image, address, size, executable=True):
    base, sections = pe_sections(image)
    if not 0 < size <= 16384 or not base <= address < address + size <= 2**32:
        raise ValueError('stdio evidence range/budget')
    rva = address - base
    matches = []
    for section in sections:
        if section['rva'] <= rva and rva + size <= section['rva'] + min(section['virtual'], section['size']):
            if executable and not section['flags'] & 0x20000000:
                raise ValueError('stdio code in nonexecutable section')
            matches.append(cut(image, section['start'] + rva - section['rva'], size))
    if len(matches) != 1:
        raise ValueError('stdio missing/ambiguous initialized range')
    return matches[0]


# These are measured linked-function extents, not accepted application IDs.
# Every call below is retained, including dependencies not yet implemented.
DEPENDENCIES = [
    ('descriptor_write', 0x40df1c, 0x40e01f),
    ('descriptor_unlock_funclet', 0x40e01f, 0x40e02d),
    ('write_selector', 0x40e02d, 0x40e249),
    ('console_selector', 0x40dba9, 0x40dc26),
    ('isatty', 0x410105, 0x41015b),
    ('stack_probe', 0x4146e0, 0x41470b),
    ('security_check', 0x40154c, 0x40155a),
    ('errno_search', 0x407b93, 0x407c12),
    ('errno_mapper', 0x407c12, 0x407c71),
    ('global_errno_update', 0x407c71, 0x407c94),
    ('errno_update', 0x407c94, 0x407cb8),
]


def extract(original, output):
    image = (original / 'unwind.exe').read_bytes()
    obj = (original / 'unwind.obj').read_bytes()
    frozen = json.loads(Path(__file__).with_name('stdio-frozen.json').read_text())
    base, _ = pe_sections(image)
    index = instructions((original / 'disasm.txt').read_text(), image)
    rows = [(r['name'], int(r['va'], 16), int(r['va'], 16) + r['size'], r['sha256'])
            for r in frozen['regions']]
    rows += [(name, start, end, None) for name, start, end in DEPENDENCIES]
    output.mkdir(parents=True, exist_ok=True)
    records = []
    for name, start, end, expected in rows:
        raw = mapped(image, start, end - start)
        if expected is not None and sha(raw) != expected:
            raise ValueError('frozen original region changed: ' + name)
        pc = start
        calls = []
        while pc < end:
            instruction = index.get(pc - base)
            if instruction is None or pc + instruction['size'] > end:
                raise ValueError('stdio region is not complete original instructions: ' + name)
            data = bytes.fromhex(instruction['code_hex'])
            if mapped(image, pc, len(data)) != data:
                raise ValueError('stdio disassembly/image disagreement')
            if len(data) == 5 and data[0] == 0xe8:
                target = (pc + 5 + int.from_bytes(data[1:], 'little', signed=True)) & 0xffffffff
                calls.append(dict(site=pc, kind='direct', target=target))
            elif len(data) == 6 and data[:2] == b'\xff\x15':
                calls.append(dict(site=pc, kind='import', target=int.from_bytes(data[2:], 'little')))
            pc += len(data)
        filename = name + '.bin'
        (output / filename).write_bytes(raw)
        records.append(dict(name=name, va=start, size=len(raw), sha256=sha(raw), file=filename,
                            calls=calls, effects_proven=False))
    result = dict(schema=1, kind='original CRT component extraction; not whole-PE eligibility',
                  pe_sha256=sha(image), object_sha256=sha(obj),
                  frozen_reference_pe_sha256=frozen['artifact']['pe_sha256'],
                  reference_identity_matches=sha(image) == frozen['artifact']['pe_sha256'],
                  image_base=base, regions=records, whole_pe_translation_pairs=0,
                  emission_allowed=False)
    # Measurement bindings only. The Rust component proves all operand uses.
    bindings = dict(cookie=0x41c000, descriptor_table=0x41cf08,
                    write_iat=0x415080, error_iat=0x415044,
                    descriptor_limit_address=0x41d108, descriptor_limit=1,
                    module_begin=base, module_end=base+u32(image,u32(image,60)+80))
    if not base < bindings['module_end'] <= 0xffffffff:
        raise ValueError('stdio image extent overflow')
    for field, expected in [('write_iat', ('kernel32.dll', 'WriteFile')),
                            ('error_iat', ('kernel32.dll', 'GetLastError'))]:
        if tuple(import_at_iat(image, bindings[field] - base)) != expected:
            raise ValueError('original CRT import identity: ' + field)
    result['component_bindings'] = bindings
    error_table=mapped(image,0x416038,360,executable=False)
    (output/'errno_table.bin').write_bytes(error_table)
    records.append(dict(name='errno_table',va=0x416038,size=len(error_table),sha256=sha(error_table),
                        file='errno_table.bin',calls=[],effects_proven=False))
    lines = [f"region {r['name']} {r['va']} {r['file']}" for r in records]
    lines += [f"binding {name} {value}" for name, value in bindings.items()]
    (output / 'stdio.manifest').write_text('\n'.join(lines) + '\n')
    (output / 'stdio-binding.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = extract(args.original, args.output)
    print(json.dumps(dict(pe_sha256=result['pe_sha256'], regions=len(result['regions']),
                          emission_allowed=False)))
