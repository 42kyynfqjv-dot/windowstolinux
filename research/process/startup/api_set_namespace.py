"""Validate observations; never grant initialization or native-call authority."""
CONTRACTS = ('api-ms-win-core-synch-l1-2-0', 'api-ms-win-core-fibers-l1-1-1',
             'api-ms-win-core-heap-l1-1-0', 'api-ms-w2l-missing-contract-l9-9-9')
SYMBOLS = ('InitializeCriticalSectionEx', 'FlsAlloc', 'HeapAlloc', 'NoSuchExport')

def validate(report):
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
            if item['machine'] != 0x14c or len(item['sha256']) != 64 or any(c not in '0123456789abcdef' for c in item['sha256']):
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
