"""Retained original Windows API evidence; never translation comparisons."""
import hashlib
import json
from pathlib import Path

EXPECTATIONS = Path(__file__).parent/'evidence/argv-conversion-expectations.json'
KIND = 'original Windows file-mode and UTF8 API observations; no PE translation'


def narrow_conversion_observations(path):
    raw = Path(path).read_bytes()
    rows = [json.loads(line) for line in raw.splitlines()]
    cases = json.loads(EXPECTATIONS.read_text())['cases']
    if len(rows) != 1+len(cases) or not all(isinstance(r, dict) for r in rows):
        raise ValueError('narrow conversion original observation count/type')
    h = rows[0]
    if h.get('kind') != KIND or h.get('arch') not in ('x86', 'x86_64', 'aarch64'):
        raise ValueError('narrow conversion original provenance')
    for key in ('initial_ansi_raw', 'oem_raw', 'ansi_raw', 'restored_raw'):
        if type(h.get(key)) is not int or not -(1 << 31) <= h[key] < (1 << 31):
            raise ValueError('file API raw BOOL domain')
    if h['oem_raw'] != 0 or h['ansi_raw'] == 0 or ((h['initial_ansi_raw'] != 0) != (h['restored_raw'] != 0)):
        raise ValueError('file API mode/restore effects')
    for key in ('acp', 'oemcp'):
        if type(h.get(key)) is not int or not 0 < h[key] <= 0xffffffff:
            raise ValueError('original code page domain')
    owner = h.get('export_owner_utf16')
    if (not isinstance(owner, list) or not 0 < len(owner) < 1024
            or any(type(n) is not int or not 0 < n <= 65535 for n in owner)):
        raise ValueError('original export owner name')
    b''.join(n.to_bytes(2, 'little') for n in owner).decode('utf-16le')
    for row, case in zip(rows[1:], cases):
        for key in ('label', 'utf16', 'input_count', 'flags', 'capacity', 'query_nonnull'):
            if type(row.get(key)) is not type(case[key]) or row[key] != case[key]:
                raise ValueError('original narrow conversion input schedule')
        if any(type(n) is not int for n in row['utf16']):
            raise ValueError('original UTF16 unit type')
        supported_flags = case['flags'] in (0, 128)
        capacity = case['capacity']
        if (type(row.get('result')) is not int or not 0 <= row['result'] <= max(capacity, case['expected_return'])
                or (supported_flags and row['result'] != case['expected_return'])
                or type(row.get('last_error')) is not int or not 0 <= row['last_error'] <= 0xffffffff
                or (supported_flags and case['expected_error'] is not None and row['last_error'] != case['expected_error'])):
            raise ValueError('original narrow conversion result/error')
        data = row.get('bytes')
        capacity = case['capacity']
        if (not isinstance(data, list) or len(data) != capacity+4
                or any(type(n) is not int or not 0 <= n <= 255 for n in data)
                or data[capacity:] != [0x5a]*4):
            raise ValueError('original narrow conversion output bounds')
        if supported_flags and capacity and row['result'] > 0:
            payload = case['expected_payload']
            if data != payload + [0x5a]*(capacity+4-len(payload)):
                raise ValueError('original narrow conversion output bytes')
        # Outside documented flag domain, collect results only. The original
        # flag16/error1004 expectation was refuted by the preserved Windows run;
        # this does not admit flag16 in any converter binding.
        # Failure bytes INSIDE capacity are retained, not assumed unchanged.
        # Successful LastError is also unconstrained; it is not a failure code.
    return hashlib.sha256(raw).hexdigest()
