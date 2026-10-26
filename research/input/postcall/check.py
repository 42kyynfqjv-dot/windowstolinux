"""Bind design evidence to trusted CI artifacts, never grant PE eligibility."""
import hashlib
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FROZEN = HERE.parent / 'heldout'
FIRST = {
    ('shared', 'O1'): '1000', ('shared', 'O2'): '103f',
    ('nested', 'O1'): '1016', ('nested', 'O2'): '107b',
    ('composed', 'O1'): '1000', ('composed', 'O2'): '104b',
    ('larger', 'O1'): '1000', ('larger', 'O2'): '1000',
}


def checked(condition, message):
    if not condition:
        raise ValueError(message)


def u16(data, offset):
    return struct.unpack_from('<H', data, offset)[0]


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def code_bytes(data):
    # This is an evidence reader for trusted compiler artifacts, not a PE loader.
    checked(data[:2] == b'MZ', 'MZ')
    pe = u32(data, 60)
    checked(data[pe:pe+4] == b'PE\0\0' and u16(data, pe+4) == 0x14c, 'PE32 x86')
    checked(u16(data, pe+24) == 0x10b and u32(data, pe+40) == 0x1000, 'entry')
    table = pe + 24 + u16(data, pe+20)
    sections = [table + i * 40 for i in range(u16(data, pe+6))]
    text = [p for p in sections if data[p:p+8] == b'.text\0\0\0']
    checked(len(text) == 1, 'unique .text')
    p = text[0]
    size, rva, raw_size, raw = (u32(data, p+i) for i in (8, 12, 16, 20))
    checked(rva == 0x1000 and size == 159 and raw_size >= size and raw+raw_size <= len(data), 'code range')
    return data[raw:raw+size]


def inventory(root):
    frozen = json.loads((FROZEN / 'frozen.json').read_text(encoding='utf-8'))
    for name, digest in frozen['sha256'].items():
        checked(hashlib.sha256((FROZEN / name).read_bytes()).hexdigest() == digest, 'frozen bytes')
    report = json.loads((root / 'held-input.json').read_text(encoding='utf-8'))
    checked(report['manifest'] == frozen, 'manifest identity')
    rows = report['programs']
    cases = {r['name']: r['vectors'] for r in json.loads((FROZEN / 'cases.json').read_text(encoding='utf-8'))}
    checked(len(rows) == 8 and {(r['name'], r['config']) for r in rows} == set(FIRST), 'eight unique artifacts')
    bound = []
    for row in rows:
        key = row['name'], row['config']
        data = (root / f'div_hold_{key[0]}_{key[1]}.exe').read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        checked(digest == row['pe_sha256'], 'unchanged PE hash')
        checked(row['source_sha256'] == frozen['sha256'][key[0]+'.c'], 'source hash')
        accepted = key == ('composed', 'O2')
        checked(row['accepted'] is accepted and row['converter_error'] == ('' if accepted else
                f'w2l: input: unsupported instruction at {FIRST[key]}\n'), 'production outcome')
        checked(len(row['observations']) == 14, 'original-only scenario count')
        for index, (observation, expected) in enumerate(zip(row['observations'], cases[key[0]])):
            checked(observation == {'index': index, 'exit': expected['exit'],
                                    'stdout_hex': expected['stdout_hex'],
                                    'stderr_hex': expected['stderr_hex']}, 'frozen Windows outcome')
        bound.append({'name': key[0], 'config': key[1], 'pe_sha256': digest,
                      'first_decoder_rejection': FIRST[key], 'accepted': accepted})
        if key == ('composed', 'O2'):
            code = code_bytes(data)
    forms = json.loads((HERE / 'forms.json').read_text(encoding='utf-8'))
    covered = set()
    for row in forms['instructions'] + [forms['padding']]:
        start = int(row['rva'], 16) - 0x1000
        expected = bytes.fromhex(row['bytes'])
        checked(code[start:start+len(expected)] == expected, 'literal instruction bytes at '+row['rva'])
        occupied = set(range(start, start+len(expected)))
        checked(not (covered & occupied), 'overlapping inventory')
        covered |= occupied
    checked(covered == set(range(len(code))), 'complete byte inventory')
    checked(sum(r['new_form'] for r in forms['instructions']) == 7, 'seven new forms')
    return {'scope': 'SUB-562 inventory binding; execution comparisons are separately required',
            'artifacts': bound, 'instructions': len(forms['instructions']),
            'new_forms': 7, 'padding_bytes': 15,
            'composed_code_sha256': hashlib.sha256(code).hexdigest(),
            'inventory_sha256': hashlib.sha256((HERE / 'forms.json').read_bytes()).hexdigest()}


if __name__ == '__main__':
    root = Path(sys.argv[1])
    result = inventory(root)
    destination = root / 'postcall-design.json'
    if '--compare' in sys.argv:
        checked(json.loads(destination.read_text(encoding='utf-8')) == result, 'same artifact design report across hosts')
    else:
        destination.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print('POSTCALL DESIGN:', result['instructions'], 'literal instructions, 7 new forms, 15 padding bytes; 1 accepted artifact; 7 artifacts still rejected')
