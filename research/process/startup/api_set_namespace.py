"""Validate observations; never grant initialization or native-call authority."""
import json
from pathlib import Path

CONTRACTS = ('api-ms-win-core-synch-l1-2-0', 'api-ms-win-core-fibers-l1-1-1',
             'api-ms-win-core-heap-l1-1-0', 'api-ms-w2l-missing-contract-l9-9-9')
SYMBOLS = ('InitializeCriticalSectionEx', 'FlsAlloc', 'HeapAlloc', 'NoSuchExport')

def digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)

def validate(report):
    frozen = json.loads(Path(__file__).with_name('api-set-frozen.json').read_text())
    if report['source_sha256'] != frozen['source_sha256'] or not digest(report['pe_sha256']) or not digest(report['compiler_sha256']):
        raise ValueError('observer source/compiler/artifact provenance')
    if type(report['translated_pairs']) is not int or report['translated_pairs'] != 0:
        raise ValueError('observer is not translated evidence')
    if report['windows_version'][:3] != [10, 0, 20348] or report['machine'] != 0x14c:
        raise ValueError('unmeasured Windows version/architecture')
    rows = report['rows']
    if len(rows) != len(CONTRACTS) or [r['contract'] for r in rows] != list(CONTRACTS):
        raise ValueError('missing/ambiguous contract observations')
    mapping = {}
    for i, row in enumerate(rows):
        if row['symbol'] != SYMBOLS[i] or row['flags'] != 0x800:
            raise ValueError('symbol/flags mismatch')
        if i == 3:
            if row['loaded'] is not False or type(row['error']) is not int or not 0 < row['error'] <= 0xffffffff:
                raise ValueError('missing contract did not fail')
            continue
        if any(row[key] is not True for key in ('loaded', 'same_handle', 'export_survives_one_release')):
            raise ValueError('load/reference/export observation failed')
        for key in ('load_host', 'export_host', 'ntdll'):
            item = row[key]
            if item['machine'] != 0x14c or not digest(item['sha256']):
                raise ValueError('module architecture/hash provenance')
        mapping[row['contract']] = dict(load_host=row['load_host'], export_host=row['export_host'])
    if len({r['ntdll']['sha256'] for r in rows[:3]}) != 1:
        raise ValueError('mixed runtime identity')
    return dict(mapping=mapping, initialization='unproved', native_admission=False)

def authorize_native(report, initialization):
    validate(report)
    # Neither a successful observation nor a caller-supplied success flag is
    # an issuer of a closed module-initialization/export implementation proof.
    raise ValueError('native provider initialization/effect proof unbound')
