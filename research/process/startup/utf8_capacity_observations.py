"""Validate original API input schedule and bounded effects, not a translator."""
import hashlib
import json
from pathlib import Path

EXPECTATIONS = Path(__file__).parent/'evidence/utf8-capacity-expectations.json'
KIND = 'original Windows UTF8 capacity/error observations; no PE translation'


def schedule():
    data = json.loads(EXPECTATIONS.read_text())
    return [(v, flags, cap) for v in data['vectors'] for flags in data['flags'] for cap in v['capacities']]


def utf8_capacity_observations(path):
    raw = Path(path).read_bytes()
    rows = [json.loads(line) for line in raw.splitlines()]
    cases = schedule()
    if len(rows) != len(cases)+1 or not all(isinstance(row, dict) for row in rows):
        raise ValueError('UTF8 capacity observation record count/type')
    if rows[0].get('kind') != KIND or rows[0].get('arch') not in ('x86', 'x86_64', 'aarch64'):
        raise ValueError('UTF8 capacity original provenance')
    for row, (v, flags, cap) in zip(rows[1:], cases):
        expected = dict(label=v['label'], utf16=v['utf16'], input_count=v['input_count'], flags=flags, capacity=cap)
        if any(type(row.get(k)) is not type(value) or row[k] != value for k, value in expected.items()):
            raise ValueError('UTF8 capacity input schedule')
        if any(type(n) is not int for n in row['utf16']):
            raise ValueError('UTF8 capacity input unit types')
        result = row.get('result')
        error = row.get('last_error')
        output = row.get('bytes')
        if (type(result) is not int or not 0 <= result <= len(v['payload'])
                or type(error) is not int or not 0 <= error <= 0xffffffff
                or not isinstance(output, list) or len(output) != cap+4
                or any(type(n) is not int or not 0 <= n <= 255 for n in output)
                or output[cap:] != [0x5a]*4):
            raise ValueError('UTF8 capacity result/output bounds')
        if not v['invalid_utf16'] or flags == 0:
            if cap == 0 or cap >= len(v['payload']):
                if result != len(v['payload']):
                    raise ValueError('UTF8 capacity complete/query count')
                if cap and output != v['payload']+[0x5a]*(cap+4-len(v['payload'])):
                    raise ValueError('UTF8 capacity complete bytes')
            elif result != 0 or error != 122:
                raise ValueError('UTF8 capacity insufficient result/error')
        # Strict-invalid results and all bytes inside failed-call capacity are
        # observations only. No undocumented atomicity/prefix rule is assumed.
    return hashlib.sha256(raw).hexdigest()
