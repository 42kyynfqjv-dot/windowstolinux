"""Additional native inputs with an independent decimal-task specification.

These are NOT additional Windows comparisons. The eight unchanged PEs and their
112 original comparisons are verified by measure.py before this check runs.
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
report = json.loads((root / 'held-input-native.json').read_text(encoding='utf-8'))
frozen = {r['name']: {v['value'] for v in r['vectors']} for r in json.loads((Path(__file__).parent / 'cases.json').read_text(encoding='utf-8'))}
values = [None, ''] + [str(i) for i in range(10)] + [f'{i:02}' for i in range(100)]
values += ['123', '999', '1234', '9999', '12345', '0/', '/0', 'a', '９', '😀', 'A€😀', '7' * 64]

def expected(name, text):
    if text is None or text == '':
        return 200
    units = len(text.encode('utf-16-le')) // 2
    limit = 4 if name == 'larger' else 2
    if units > limit:
        return 201
    if any(c not in '0123456789' for c in text):
        return 202
    # Independent specification, not converter expressions or a machine interpreter.
    digits = [ord(c) - ord('0') for c in text]
    if name == 'larger':
        return sum(digits)
    number = int(text, 10)
    return {'shared': number + digits[0], 'nested': number,
            'composed': number * 2 + 6}[name]

records = []
for item in report['programs']:
    assert item['accepted']
    stem = f"div_hold_{item['name']}_{item['config']}"
    binary = root / (stem + '-native')
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == item['elf_sha256']
    for value in values:
        env = {} if value is None else {'W2L_INPUT': value}
        result = subprocess.run([str(binary.resolve())], env=env, capture_output=True, timeout=30)
        wanted = expected(item['name'], value)
        assert (result.returncode, result.stdout, result.stderr) == (wanted, b'', b''), (stem, value, result)
    records.append({'name': item['name'], 'config': item['config'], 'pe_sha256': item['pe_sha256'],
                    'elf_sha256': item['elf_sha256'], 'native_cases': len(values), 'outside_frozen_cases': len(set(values) - frozen[item['name']])})
assert len(records) == 8
out = {'scope': 'additional native cases, not Windows pairs', 'records': records,
       'native_cases': sum(r['native_cases'] for r in records),
       'outside_frozen_cases': sum(r['outside_frozen_cases'] for r in records)}
(root / 'composition-additional.json').write_text(json.dumps(out, indent=2) + '\n', encoding='utf-8')
print('COMPOSITION ADDITIONAL:', out['native_cases'], 'native runs (includes frozen overlap);', out['outside_frozen_cases'], 'outside frozen cases; no new Windows pairs')
