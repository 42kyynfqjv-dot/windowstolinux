"""Independent documented data-page expectations, not a conversion oracle."""
import hashlib
import json
from pathlib import Path


def frozen():
    here = Path(__file__).parent
    data = json.loads((here / 'protect-frozen.json').read_text())
    if hashlib.sha256((here / 'protect_probe.c').read_bytes()).hexdigest() != data['source_sha256']:
        raise ValueError('frozen VirtualProtect observer changed')
    return data


def validate(row):
    if type(row['mode']) is not int or not 0 <= row['mode'] < 6:
        raise ValueError('protection scenario identity')
    expected = frozen()['expected'][row['mode']]
    if type(row['ok']) is not bool or any(type(x) is not int for x in row['pages'] + row['states']):
        raise ValueError('protection observation types')
    if (row['ok'] != expected['ok'] or row['states'] != expected['states']
            or len(row['pages']) != 3
            or any(want is not None and actual != want for actual, want in zip(row['pages'], expected['pages']))):
        raise ValueError('protection result/page mismatch')
    if row['ok'] and (type(row['old']) is not int or row['old'] != expected['old']):
        raise ValueError('first page old protection mismatch')
    # MEMORY_BASIC_INFORMATION.Protect is undefined for MEM_RESERVE.
    # The observed bits are retained but cannot be an equality oracle.
    # Failure old-output and LastError are retained observations, not guessed
    # contracts. Native subset rejects these paths before effects for now.
    return expected
