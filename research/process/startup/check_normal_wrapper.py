"""Compare original observed wrapper boundaries with mechanically emitted slices.

The formatter body is an explicit input boundary (observed EAX/flags). This
does not execute that body, Windows exception dispatch, or a whole PE in Rust.
"""
import argparse
import hashlib
import json
import os
import platform
import re
from pathlib import Path
import subprocess
import sys

from formatter_binding import mapped, locale_state_evidence
from coff_binding import import_at_iat, pe_sections
from observe_stdio import CASES, parse_events, summarize
from narrow_conversion_observations import narrow_conversion_observations
from utf8_capacity_observations import utf8_capacity_observations
from replay_source_guard import ReplaySourceGuard


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def observations(directory):
    report = json.loads((directory/'report.json').read_text())
    if report.get('kind') != 'separately instrumented original CRT observations; no whole-PE translations':
        raise ValueError('wrapper comparison requires original observer evidence, not synthetic vectors')
    if [r.get('label') for r in report['runs']] != [*CASES, 'cleanup-failure']:
        raise ValueError('wrapper original observation labels/order')
    observed = []
    for record in report['runs']:
        label = record['label']
        raw = (directory/label/'observer.stdout').read_bytes()
        if record['observer_stdout_sha256'] != sha(raw):
            raise ValueError('wrapper raw observation hash changed')
        cleanup = label == 'cleanup-failure'
        rows = parse_events(raw, 'baseline' if cleanup else label, report, cleanup)
        if not cleanup:
            actual = summarize(rows, label, report)
            if actual != record['observed']:
                raise ValueError('wrapper summary differs from original raw observations')
            observed.append(actual['wrapper'])
    return report, observed


def require_test_completions(result, required):
    """Require actual named passes and a consistent successful libtest summary.

    New tests may be added without making a stale hardcoded count reject a
    successful run. Missing tests, ignored tests and false success still reject.
    """
    rows = re.findall(rb'^test ([^\r\n ]+) \.\.\. ok\r?$', result.stdout, re.M)
    summary = re.findall(rb'^test result: ok\. (\d+) passed; 0 failed; 0 ignored;', result.stdout, re.M)
    if (result.returncode or len(summary) != 1 or int(summary[0]) != len(rows)
            or len(rows) != len(set(rows)) or not set(required).issubset(rows)):
        raise ValueError('original C++ owned record component failed: named completions/summary')


def image_name_observations(path):
    """Validate retained original API bytes; these are never PE translations."""
    raw = Path(path).read_bytes()
    rows = [json.loads(line) for line in raw.splitlines()]
    kind = 'original Windows GetModuleFileNameW API component; no PE translation'
    def words(value):
        return (isinstance(value, list) and len(value) <= 32770
                and all(type(n) is int and 0 <= n <= 65535 for n in value))
    if len(rows) != 7 or not all(isinstance(row, dict) for row in rows):
        raise ValueError('image-name observation row count/type')
    baseline = rows[0].get('baseline_utf16')
    if (rows[0].get('kind') != kind or not isinstance(rows[0].get('arch'), str)
            or not rows[0]['arch'] or not words(baseline) or not 0 < len(baseline) <= 32765
            or 0 in baseline):
        raise ValueError('image-name original baseline provenance/domain')
    b''.join(n.to_bytes(2, 'little') for n in baseline).decode('utf-16le')
    size = len(baseline)
    for row, count in zip(rows[1:], [1, 2, size, size+1, size+2, 261]):
        copied = min(size, count-1)
        expected = baseline[:copied] + [0] + [0x5a5a] * (count+2-copied)
        if (type(row.get('count')) is not int or row['count'] != count
                or type(row.get('result')) is not int or row['result'] != min(size, count)
                or type(row.get('last_error')) is not int or not 0 <= row['last_error'] <= 0xffffffff
                or (size >= count and row['last_error'] != 122)
                or not words(row.get('units')) or row['units'] != expected):
            raise ValueError('image-name original API effect/bounds mismatch')
    return sha(raw)


def check(original, observation, out, compare=None):
    source_guard = ReplaySourceGuard(Path(__file__).resolve().parents[3], out)
    out.mkdir(parents=True, exist_ok=False)
    (out/'source-manifest.json').write_text(json.dumps(source_guard.initial, indent=2)+'\n')
    image = (original/'unwind.exe').read_bytes()
    report, observed = observations(observation)
    if report['pe_sha256'] != sha(image):
        raise ValueError('wrapper comparison original PE hash mismatch')
    if len(observed) != 5:
        raise ValueError('wrapper comparison requires five labelled observations')
    vectors = [[w['cookie'], *w['saved'], w['body_eax'], w['body_flags'],
                w['return_eax'], w['return_flags'], w['caller_stack_delta']] for w in observed]
    vector_bytes = ('\n'.join(' '.join(str(n) for n in row) for row in vectors)+'\n').encode()
    if (observation/'normal-wrapper-vectors.txt').read_bytes() != vector_bytes:
        raise ValueError('wrapper vectors do not match original observations')
    (out/'cookie-initializer.bin').write_bytes(mapped(image, 0x401b71, 75, executable=True))
    (out/'cookie-entropy.bin').write_bytes(mapped(image, 0x401b24, 77, executable=True))
    for name,address,size in [('entry-shim',0x4017a4,10),('startup-prefix',0x40161f,19),('startup-initializer',0x401945,57),('startup-cpu-prefix',0x401ea5,31),('startup-cpu-tail',0x401ec4,763)]:
        (out/(name+'.bin')).write_bytes(mapped(image,address,size,executable=True))

    for name,address,size in [("modules",0x4024ca,31),("locks",0x4029b4,60),("destroy",0x4029f0,47),("fls",0x402963,51),("release",0x402996,30),("constructor_prefix",0x402c2d,71),("fls_alloc",0x402b3e,59),("fls_set",0x402bef,62)]:
        (out/("startup-"+name+".bin")).write_bytes(mapped(image,address,size,executable=True))
    cpu_base, _ = pe_sections(image)
    if tuple(import_at_iat(image,0x41501c-cpu_base)) != ('kernel32.dll','IsProcessorFeaturePresent'):
        raise ValueError('startup processor feature import identity')
    (out/'startup-cpu-import.txt').write_text('41501c kernel32.dll IsProcessorFeaturePresent\n')
    if tuple(import_at_iat(image,0x4150e0-cpu_base)) != ('kernel32.dll','WideCharToMultiByte'):
        raise ValueError('argv wide conversion import identity')
    cookie_imports = []
    cookie_base, _ = pe_sections(image)
    for address, name in [(0x41502c,'GetSystemTimeAsFileTime'),(0x415028,'GetCurrentThreadId'),(0x415024,'GetCurrentProcessId'),(0x415020,'QueryPerformanceCounter')]:
        library, actual = import_at_iat(image, address-cookie_base)
        if library.lower() != 'kernel32.dll' or actual != name:
            raise ValueError('cookie entropy import binding changed')
        cookie_imports.append(f'{address:x} {library} {actual}')
    (out/'cookie-imports.txt').write_text('\n'.join(cookie_imports)+'\n')

    helper = mapped(image, 0x401e60, 69, executable=True)
    epilog = mapped(image, 0x404696, 18, executable=True)
    (out/'helper.bin').write_bytes(helper)
    (out/'epilog.bin').write_bytes(epilog)
    scope_store = mapped(image, 0x402355, 3, executable=True)
    (out/'handler-scope-store.bin').write_bytes(scope_store)
    (out/'owned-notification.bin').write_bytes(mapped(image,0x402a30,31,executable=True))
    (out/'owned-nested-handler.bin').write_bytes(mapped(image,0x4027b0,70,executable=True))
    for name,va in [('CleanupA',0x401000),('CleanupB',0x401020),('CleanupC',0x401040)]:
        (out/('owned-'+name+'.bin')).write_bytes(mapped(image,va,24,executable=True))
    (out/'owned-local-body.bin').write_bytes(mapped(image,0x402710,159,executable=True))
    local_store=mapped(image,0x402775,3,executable=True)
    (out/'local-level-store.bin').write_bytes(local_store)
    (out/'handler-prolog.bin').write_bytes(mapped(image, 0x402210, 6, executable=True))
    (out/'handler-installer.bin').write_bytes(mapped(image, 0x402263, 15, executable=True))
    (out/'event-normalizer.bin').write_bytes(mapped(image, 0x414a1b, 119, executable=True))
    (out/'original-guard-validator.bin').write_bytes(mapped(image, 0x4021d0, 50, executable=True))
    (out/'original-security-check.bin').write_bytes(mapped(image, 0x40154c, 14, executable=True))
    (out/'file-scope-header.bin').write_bytes(mapped(image, 0x41b400, 16))
    (out/'file-scope-table.bin').write_bytes(mapped(image, 0x41b400, 28))
    (out/'original-handler-prefix.bin').write_bytes(mapped(image, 0x402210, 98, executable=True))
    (out/'original-context-check.bin').write_bytes(mapped(image, 0x402877, 48, executable=True))
    (out/'original-filter-bridge.bin').write_bytes(mapped(image, 0x402800, 23, executable=True))
    (out/'main-filter-0.bin').write_bytes(mapped(image, 0x401333, 41, executable=True))
    (out/'main-prolog.bin').write_bytes(mapped(image, 0x401280, 57, executable=True))
    (out/'Inner-prolog.bin').write_bytes(mapped(image, 0x4010c0, 48, executable=True))
    finally_regions = {}
    for name,at,size,executable in [('inner-scalar-init',0x4010f0,28,True),
                                     ('inner-finally-1',0x40116e,17,True),
                                     ('inner-finally-0',0x40117f,33,True),
                                     ('finally-dispatch',0x401060,93,True),
                                     ('finally-dispatch-table',0x415180,24,False),
                                     ('Inner-scope-table',0x41b1d0,40,False),
                                     ('handler_saved_entry',0x402210,12,True),
                                     ('handler_disposition_init',0x402222,7,True),
                                     ('handler_original_epilog',0x4022e0,10,True)]:
        raw=mapped(image,at,size,executable=executable)
        (out/(name+'.bin')).write_bytes(raw)
        finally_regions[name]=sha(raw)

    (out/'main-activate.bin').write_bytes(mapped(image, 0x40130f, 7, executable=True))
    (out/'Main-scope-header.bin').write_bytes(mapped(image, 0x41b218, 16))
    (out/'Main-scope-table.bin').write_bytes(mapped(image, 0x41b218, 28))
    (out/'original-unwind-caller.bin').write_bytes(mapped(image,0x4022bd,45,executable=True))
    (out/'original-finally-bridge.bin').write_bytes(mapped(image,0x402a50,3,executable=True))
    (out/'original-local-wrapper.bin').write_bytes(mapped(image,0x402860,23,executable=True))
    (out/'handler-complete.bin').write_bytes(mapped(image, 0x402210, 350, executable=True))
    (out/'original-landing-pivot.bin').write_bytes(mapped(image,0x40135c,3,executable=True))
    (out/'original-landing-context.bin').write_bytes(mapped(image,0x40135f,57,executable=True))
    for name,at,n in [('printf-routing',0x401520,44),('printf-iob',0x4045d8,16),('printf-options',0x401270,6),('printf-entry',0x40643e,164),('printf-context',0x4051e0,93)]:
        (out/(name+'-live.bin')).write_bytes(mapped(image,at,n,executable=True))
    (out/'main-completion-live.bin').write_bytes(mapped(image,0x4013b7,357,executable=True))
    (out/'main-security-live.bin').write_bytes(mapped(image,0x40154c,14,executable=True))
    (out/'main-format-live.bin').write_bytes(mapped(image,0x4151a0,278))
    (out/'main-initial-live.bin').write_bytes(mapped(image,0x4012b9,0x401316-0x4012b9,executable=True))
    (out/'main-fill-live.bin').write_bytes(mapped(image,0x402370,0x4024ca-0x402370,executable=True))
    if tuple(import_at_iat(image,0x415008-pe_sections(image)[0]))!=('kernel32.dll','GetModuleHandleW'): raise ValueError('original current-module import identity changed')
    (out/'initial-raise-pushes.bin').write_bytes(mapped(image,0x40110c,11,executable=True))
    (out/'initial-raise-call.bin').write_bytes(mapped(image,0x401117,6,executable=True))
    if tuple(import_at_iat(image,0x415000-pe_sections(image)[0]))!=('kernel32.dll','RaiseException'): raise ValueError('original RaiseException import identity changed')
    (out/'original-restore-call.bin').write_bytes(mapped(image,0x401398,6,executable=True))
    (out/'original-restore.bin').write_bytes(mapped(image,0x401250,28,executable=True))
    (out/'original-restored-landing.bin').write_bytes(mapped(image,0x4013a5,18,executable=True))
    (out/'original-selected-transfer.bin').write_bytes(mapped(image,0x402820,25,executable=True))
    (out/'global-wrapper.bin').write_bytes(mapped(image, 0x402840, 26, executable=True))
    if tuple(import_at_iat(image,0x415040-pe_sections(image)[0]))!=('kernel32.dll','RtlUnwind'): raise ValueError('original RtlUnwind import identity changed')
    # These new native cases execute original outer FILE scope code with an
    # explicitly supplied driver. They are NOT additional Windows comparisons.
    base, _ = pe_sections(image)
    file_imports = {}
    for address, expected in [(0x41504c, ('kernel32.dll', 'EnterCriticalSection')),
                              (0x415050, ('kernel32.dll', 'LeaveCriticalSection'))]:
        actual_import = tuple(import_at_iat(image, address-base))
        if actual_import != expected:
            raise ValueError('FILE scope original import identity mismatch')
        file_imports[str(address)] = list(actual_import)
    construction_thunk = mapped(image, 0x408079, 12, executable=True)
    if construction_thunk != bytes.fromhex('8bff558bec5dff25ac504100'):
        raise ValueError('original FILE construction thunk changed')
    if tuple(import_at_iat(image, 0x4150ac-base)) != ('kernel32.dll', 'InitializeCriticalSectionEx'):
        raise ValueError('original FILE construction import changed')
    file_regions = {'file-construction-thunk': sha(construction_thunk)}
    standard = mapped(image, 0x4085e7, 176, executable=True)
    test_source = (Path(__file__).resolve().parents[3]/'src/crt_standard_handles_tests.rs').read_text()
    fixture = re.search(r'let bytes:Vec<u8>="([0-9a-f]+)"', test_source)
    if fixture is None or bytes.fromhex(fixture[1]) != standard:
        raise ValueError('standard-handle test fixture differs from original PE')
    for va, name in [(0x41507c, 'GetStdHandle'), (0x4150bc, 'GetFileType')]:
        if tuple(import_at_iat(image, va-base)) != ('kernel32.dll', name):
            raise ValueError('standard-handle original import changed')
    file_regions['standard-handle-initializer'] = sha(standard)
    inherited = mapped(image, 0x408537, 176, executable=True)
    inherited_fixture = re.search(r'let inherited:Vec<u8>="([0-9a-f]+)"', test_source)
    if inherited_fixture is None or bytes.fromhex(inherited_fixture[1]) != inherited:
        raise ValueError('inherited-handle fixture differs from original PE')
    if tuple(import_at_iat(image, 0x415038-base)) != ('kernel32.dll', 'GetStartupInfoW'):
        raise ValueError('inherited startup-info import changed')
    file_regions['inherited-handle-initializer'] = sha(inherited)
    manager_prefix = mapped(image, 0x40bf2a, 12, executable=True)
    if manager_prefix != bytes.fromhex('6a1068a0b64100e82a5fffff'):
        raise ValueError('manager allocation/scope/prolog binding changed')
    file_regions['manager-prefix'] = sha(manager_prefix)
    manager_epilog = mapped(image, 0x40bf50, 16, executable=True)
    normal_source = (Path(__file__).resolve().parents[3]/'src/crt_normal_frame_tests.rs').read_text()
    fixture = re.search(r'let\s+manager_epilog_bytes\s*=\s*bytes_hex\("([0-9a-f]+)"\)', normal_source)
    if fixture is None or bytes.fromhex(fixture[1]) != manager_epilog:
        raise ValueError('manager epilog fixture differs from original PE')
    file_regions['manager-epilog'] = sha(manager_epilog)
    for name,start,iat,api in [('global_enter',0x40bdcf,0x41504c,'EnterCriticalSection'),
                               ('global_leave',0x40be17,0x415050,'LeaveCriticalSection')]:
        raw=mapped(image,start,23,executable=True)
        fixture=re.search(r'let\s+'+name+r'\s*:\s*Vec<u8>\s*=\s*"([0-9a-f]+)"',test_source)
        if fixture is None or bytes.fromhex(fixture[1])!=raw:
            raise ValueError('indexed global-lock helper fixture differs from original PE')
        if tuple(import_at_iat(image,iat-base))!=('kernel32.dll',api):
            raise ValueError('indexed global-lock API identity changed')
        file_regions[name]=sha(raw)


    for name,start,length in [('heap_producer',0x40c8f0,17),('calloc_body',0x407cf0,96),('mode_getter',0x4071c0,7),('errno_router',0x407ccd,21)]:
        raw=mapped(image,start,length,executable=True)
        fixture=re.search(r'let\s+'+name+r'\s*:\s*Vec<u8>\s*=\s*"([0-9a-f]+)"',test_source)
        if fixture is None or bytes.fromhex(fixture[1])!=raw:
            raise ValueError('heap/allocator fixture differs from original PE')
        file_regions[name]=sha(raw)
    abort_source = (Path(__file__).resolve().parents[3]/'src/crt_abort.rs').read_text()
    for name, start, length in [('ENTRY',0x4077ff,5),('QUERY',0x40cbcf,39),('LOCKED',0x40cafd,89),('UNLOCK',0x40cb59,12),('SCOPE',0x41b740,28),('ABORT',0x4077ff,67),('EXIT',0x407004,22)]:
        raw = mapped(image,start,length,executable=name!='SCOPE')
        fixture = re.search(r'const\s+'+name+r'\s*:\s*&str\s*=\s*"([0-9a-f]+)"',abort_source)
        if fixture is None or bytes.fromhex(fixture[1]) != raw:
            raise ValueError('abort entry/query differs from original PE')
        file_regions['abort-'+name.lower()] = sha(raw)
    exit_source = (Path(__file__).resolve().parents[3]/'src/crt_exit.rs').read_text()
    for name,start,length in [('PREFIX',0x406e69,39),('FRONT',0x406e90,79),('RETURN',0x406f09,13)]:
        raw = mapped(image,start,length,executable=True)
        fixture = re.search(r'const\s+'+name+r'\s*:\s*&str\s*=\s*"([0-9a-f]+)"',exit_source)
        if fixture is None or bytes.fromhex(fixture[1]) != raw:
            raise ValueError('shared exit instruction region differs from original PE')
        file_regions['shared-exit-'+name.lower()] = sha(raw)
    image_query_source = (Path(__file__).resolve().parents[3]/'src/crt_module_image.rs').read_text()
    raw = mapped(image,0x401d51,66,executable=True)
    fixture = re.search(r'const\s+QUERY\s*:\s*&str\s*=\s*"([0-9a-f]+)"',image_query_source)
    if fixture is None or bytes.fromhex(fixture[1]) != raw:
        raise ValueError('managed image query differs from original PE')
    if tuple(import_at_iat(image,0x15008)) != ('kernel32.dll','GetModuleHandleW'):
        raise ValueError('managed image query API identity changed')
    file_regions['managed-image-query'] = sha(raw)
    ptd_source = (Path(__file__).resolve().parents[3]/'src/crt_ptd.rs').read_text()
    for name, start, length in [('PROLOG', 0x414268, 51), ('EPILOG', 0x414254, 20), ('GETTER', 0x40a332, 135), ('FLS_THUNK', 0x408061, 12), ('LAZY', 0x40a1ee, 168), ('SET_THUNK', 0x40806d, 12)]:
        raw = mapped(image, start, length, executable=True)
        fixture = re.search(r'const\s+'+name+r'\s*:\s*&str\s*=\s*"([0-9a-f]+)"', ptd_source)
        if fixture is None or bytes.fromhex(fixture[1]) != raw:
            raise ValueError('PTD continuation/getter fixture differs from original PE')
        file_regions['ptd-'+name.lower().replace('_', '-')] = sha(raw)
    cxx_source = (Path(__file__).resolve().parents[3]/'src/crt_cxx_record.rs').read_text()
    for name, start, length, executable in [('HANDLER',0x414ad6,29,True),
            ('METADATA',0x41b42c,36,False),('UNWIND_MAP',0x41b41c,16,False),
            ('ACTION',0x4026fc,5,True),('UNWIND_STATE_GET',0x4043e9,29,True),('UNWIND_STATE_SET',0x404406,14,True),('COMMON',0x403002,54,True),
            ('DISPATCH_THUNK',0x403e78,9,True),('DISPATCH_ENTRY',0x403d76,9,True),('CONTEXT_CHECK',0x402877,48,True),('DISPATCH_PTD_USE',0x403d8a,21,True),('DISPATCH_TAIL',0x403d9f,217,True)]:
        raw = mapped(image,start,length,executable=executable)
        fixture = re.search(r'const\s+'+name+r'\s*:\s*&str\s*=\s*"([0-9a-f]+)"',cxx_source)
        if fixture is None or bytes.fromhex(fixture[1]) != raw:
            raise ValueError('C++ record/handler evidence differs from original PE')
        file_regions['ptd-cxx-'+name.lower()] = sha(raw)
    unwind_source=(Path(__file__).resolve().parents[3]/'src/crt_cxx_unwind.rs').read_text()
    for name,start,length,executable in [('WRAPPER',0x4041a4,24,True),('BODY',0x4041bc,238,True),('SCOPE',0x41b298,40,False),('BRIDGE',0x404380,76,True),('NOTICE_PREFIX',0x402a20,12,True),('NOTICE_TAIL',0x402a3b,20,True)]:
        raw=mapped(image,start,length,executable=executable)
        fixture=re.search(r'const\s+'+name+r'\s*:\s*&str\s*=\s*"([0-9a-f]+)"',unwind_source)
        if fixture is None or bytes.fromhex(fixture[1])!=raw:
            raise ValueError('C++ unwind frame/action original bytes differ')
        file_regions['cxx-unwind-'+name.lower()]=sha(raw)
    cxx_ptd_source=(Path(__file__).resolve().parents[3]/'src/crt_cxx_ptd.rs').read_text()
    for name,start,length in [('REQUIRED',0x4028c3,14),('GETTER',0x4028d1,146),('CALLOC_THUNK',0x407850,11),('FREE_THUNK',0x407750,5)]:
        raw=mapped(image,start,length,executable=True)
        fixture=re.search(r'const\s+'+name+r'\s*:\s*&str\s*=\s*"([0-9a-f]+)"',cxx_ptd_source)
        if fixture is None or bytes.fromhex(fixture[1])!=raw:
            raise ValueError('C++ dispatcher PTD code differs from original PE')
        file_regions['cxx-dispatcher-'+name.lower()]=sha(raw)
    free_source=(Path(__file__).resolve().parents[3]/'src/crt_heap_free.rs').read_text()
    for name,start,length,executable in [('FREE',0x407d50,58,True),('MAPPER',0x407c12,95,True),('SEARCH',0x407b93,127,True),('UPDATER',0x407c94,36,True),('TABLE',0x416038,360,False)]:
        raw=mapped(image,start,length,executable=executable)
        fixture=re.search(r'const\s+'+name+r'\s*:\s*&str\s*=\s*"([0-9a-f]+)"',free_source)
        if fixture is None or bytes.fromhex(fixture[1])!=raw:
            raise ValueError('original free/error-map evidence differs from PE')
        file_regions['free-'+name.lower()]=sha(raw)
    for address,name in [(0x415098,'HeapFree'),(0x415044,'GetLastError')]:
        if tuple(import_at_iat(image,address-base))!=('kernel32.dll',name):
            raise ValueError('free/error import changed')
    for address,name in [(0x415060,'TlsGetValue'),(0x415064,'TlsSetValue')]:
        if tuple(import_at_iat(image,address-base))!=('kernel32.dll',name):
            raise ValueError('C++ TLS fallback import changed; UCRT FLS is distinct')
    lookup_source=(Path(__file__).resolve().parents[3]/'src/crt_cxx_lookup.rs').read_text()
    for name,start,length in [('PREFIX',0x402a53,37),('EPILOG',0x402aca,3),('WRAPPER',0x402bb4,59),('COLD_FULL',0x402a53,160),('LOAD_HELPER',0x402af3,75),('WIDE_COMPARE',0x4078e0,67),('INDIRECT_GUARD',0x401bf9,3),('SETTER',0x402bef,62)]:
        raw=mapped(image,start,length,executable=True)
        fixture=re.search(r'const\s+'+name+r'\s*:\s*&str\s*=\s*"([0-9a-f]+)"',lookup_source)
        if fixture is None or bytes.fromhex(fixture[1])!=raw:
            raise ValueError('C++ cached resolver code differs from original PE')
        file_regions['cxx-lookup-'+name.lower()]=sha(raw)
    for address,name in [(0x41506c,'FreeLibrary'),(0x415070,'GetProcAddress'),(0x415074,'LoadLibraryExW')]:
        if tuple(import_at_iat(image,address-base))!=('kernel32.dll',name):
            raise ValueError('cold resolver module API identity changed')
    if mapped(image,0x415d54,12)!=b'FlsGetValue\0':
        raise ValueError('C++ dynamic lookup symbol changed')
    if mapped(image,0x415d68,12)!=b'FlsSetValue\0':
        raise ValueError('C++ dynamic setter symbol changed')
    # A branch into this body is not a returning cleanup receipt. Preserve its
    # complete original bytes for independent effect analysis, not execution.
    termination = mapped(image,0x40770c,60,executable=True)
    (out/'ptd-cxx-termination.bin').write_bytes(termination)
    file_regions['ptd-cxx-termination'] = sha(termination)
    locale_source = Path('src/crt_locale_startup.rs').read_text()
    for name,address in [('CALLBACK',0x40b42a),('GETTER',0x40a2ef),('HANDLER',0x414b4a),('ALIGNED_FRAME',0x40b235),('ALIGNED_EPILOG',0x40b383),('REFERENCE_BODY',0x40b38a),('SELECTED_CALLER',0x40b267),('FAST_EPILOG',0x40b381),('RESULT_CALLER',0x40b2cc),('MULTIBYTE_FLAG',0x407126),('FREE_BODY',0x407d50)]:
        literal = re.search(r'const\s+'+name+r'\s*:\s*&str\s*=\s*"([0-9a-f]+)"', locale_source)
        if literal is None:
            raise ValueError('locale startup source constant missing: '+name)
        raw = bytes.fromhex(literal[1])
        if mapped(image,address,len(raw),executable=True) != raw:
            raise ValueError('locale startup bytes differ from unchanged PE: '+name)
        (out/('locale-startup-'+name.lower()+'.bin')).write_bytes(raw)
        file_regions['locale-startup-'+name.lower()] = sha(raw)
    cp_source = Path('src/crt_locale_code_page.rs').read_text()
    for name,address in [('SELECTOR',0x40afbc),('VIEW',0x40aabe),('INITIALIZER',0x40b485),('INITIALIZER_CALL',0x40b2c7),('CLASSIFIER',0x40b090),('SECURITY',0x40154c)]:
        literal = re.search(r'const\s+'+name+r'\s*:\s*&str\s*=\s*"([0-9a-f]+)"', cp_source)
        if literal is None:
            raise ValueError('locale selector source constant missing: '+name)
        raw = bytes.fromhex(literal[1])
        if mapped(image,address,len(raw),executable=True) != raw:
            raise ValueError('locale selector bytes differ from unchanged PE: '+name)
        (out/('locale-code-page-'+name.lower()+'.bin')).write_bytes(raw)
        file_regions['locale-code-page-'+name.lower()] = sha(raw)
    malloc_source = Path('src/crt_malloc.rs').read_text()
    for name,address in [('CODE',0x408730),('MODE',0x4071c0)]:
        literal = re.search(r'const\s+'+name+r'\s*:\s*&str\s*=\s*"([0-9a-f]+)"', malloc_source)
        if literal is None:
            raise ValueError('malloc source constant missing: '+name)
        raw = bytes.fromhex(literal[1])
        if mapped(image,address,len(raw),executable=True) != raw:
            raise ValueError('malloc bytes differ from unchanged PE: '+name)
        (out/('malloc-'+name.lower()+'.bin')).write_bytes(raw)
        file_regions['malloc-'+name.lower()] = sha(raw)
    copy_source = Path('src/crt_repeat_copy.rs').read_text()
    for name,address in [('POST_ALLOC',0x40b289),('NULL_EPILOG',0x40b380)]:
        literal = re.search(r'const\s+'+name+r'\s*:\s*&str\s*=\s*"([0-9a-f]+)"', copy_source)
        if literal is None:
            raise ValueError('locale copy source constant missing: '+name)
        raw = bytes.fromhex(literal[1])
        if mapped(image,address,len(raw),executable=True) != raw:
            raise ValueError('locale copy bytes differ from unchanged PE: '+name)
        (out/('locale-copy-'+name.lower()+'.bin')).write_bytes(raw)
        file_regions['locale-copy-'+name.lower()] = sha(raw)
    # Frozen byte expectations are independent test input, not production dispatch.
    argv_requirements = json.loads((Path(__file__).parent/'evidence/argv-count-expectations.json').read_text())
    literal = re.search(r'let vectors:&\[\(&\[u8\],&\[&\[u8\]\]\)\]=&(\[.*?\]);', (Path(__file__).resolve().parents[3]/'src/crt_normal_frame_tests.rs').read_text())
    if literal is None:
        raise ValueError('argv frozen vectors missing')
    vectors = json.loads(literal[1].replace('&', '').replace('(', '[').replace(')', ']'))
    if vectors != [[v['input_utf8'], v['arguments_utf8']] for v in argv_requirements['vectors']]:
        raise ValueError('argv independent vectors changed')
    for v in argv_requirements['vectors']:
        if v['pointer_slots'] != len(v['arguments_utf8'])+1 or v['output_bytes'] != sum(len(a)+1 for a in v['arguments_utf8']):
            raise ValueError('argv independent count units')
    # Bind the new component paths to the same untouched PE, not fixture answers.
    for module, regions in [('crt_locale_shared', [('WRAPPER',0x40aeae),('CLEANUP',0x40aeef),('BODY',0x40aefb),('COPY_S',0x40b68a)]), ('crt_locale_memcpy', [('CODE',0x403040)]), ('crt_exit_tables', [('HELPER',0x4074fc),('WRAPPER',0x407565)]), ('crt_startup_caller', [('CALLER',0x401632),('LOCK',0x401913),('FLAG',0x4021bf)]), ('crt_ucrt_ptd', [('ERRNO',0x407ccd)]), ('crt_argv', [('MODE',0x401bbf),('WRAPPER',0x4069d4),('CONFIGURE',0x4066d6),('IMAGE_NAME',0x40ae0d),('LOCALE',0x40ab89),('FILE_ANSI',0x407fc0),('FILE_RESOLVE',0x407d96),('CONVERT',0x40ad10),('CONVERT_WRITE',0x40ab65),('WIDE_API',0x40b8c5),('WIDE_FLAGS',0x40b835),('COUNT',0x406813),('STORAGE',0x406985),('BYTE_CLASSIFY',0x40b70b),('BYTE_WRAPPER',0x40b75b)]), ('crt_onexit', [('ATEXIT', 4201231), ('COMMON', 4201185), ('GLOBAL', 4224168), ('WRAPPER', 4224293), ('MANAGER', 4223584), ('CLEANUP', 4223663), ('BODY', 4223675), ('RECALLOC', 4245584), ('REALLOC', 4263072), ('ENCODE', 4222306), ('MEMSET', 0x402370)]), ('crt_c_initializers', [('EMPTY',0x401e00),('LOOP', 4222156), ('POST_SLIST',0x401bc9),('POST_FLAG',0x401c1f),('POST_ENCODE',0x4066b0),('POST_NOOP',0x401bf9),('POST_FP',0x401bd8),('FP_CONTROL',0x4076a0),('FP_WORD_PREFIX',0x40d000),('FP_WORD_CONVERT',0x40d390),('THREAD_LOCALE',0x407158),('THREAD_REQUIRED',0x40a2e1),('TRUE_BYTE',0x401bd5),('ENV_THUNK',0x406c9c),('ENV_PREFIX',0x406a0b),('ENV_PRODUCER_PREFIX',0x40b966),('ENV_SCAN',0x40b92f),('ENV_TABLE',0x406a65),('ENV_TABLE_CLEANUP',0x406b4a),('ENV_STRING_COPY',0x407770),('FIRST', 4199770), ('SECOND', 4199941), ('FILE_INIT', 4211984), ('LOCALE', 4262330), ('MODE', 4243721), ('FEATURE', 4270000), ('CPP', 4199949), ('APP_TYPE', 4220462), ('GET_MODE', 4201411), ('SET_MODE', 4223062), ('ZERO', 4201404), ('GET_COMMODE', 4223487), ('ONEXIT', 4200830), ('OPTIONS', 4201474), ('OPTIONS_GET', 4199024), ('SCAN_GET', 4201468)])]:
        source = Path('src/'+module+'.rs').read_text()
        for name,address in regions:
            literal = re.search(r'const\s+'+name+r'\s*:\s*&str\s*=\s*"([0-9a-f]+)"', source)
            if literal is None:
                raise ValueError('shared locale source constant missing: '+name)
            raw = bytes.fromhex(literal[1])
            if mapped(image,address,len(raw),executable=True) != raw:
                raise ValueError('shared locale bytes differ from unchanged PE: '+name)
            label = module+'-'+name.lower()
            (out/(label+'.bin')).write_bytes(raw)
            file_regions[label] = sha(raw)
    c_array = mapped(image,0x41513c,28)
    if [int.from_bytes(c_array[n:n+4], 'little') for n in range(0,28,4)] != [0,0x40155a,0x401605,0x404510,0x4109ba,0x40c109,0x4127b0]:
        raise ValueError('original C initializer array identity')
    (out/'c-initializer-array.bin').write_bytes(c_array)
    file_regions['c-initializer-array'] = sha(c_array)
    if tuple(import_at_iat(image,0x415084-pe_sections(image)[0])) != ('kernel32.dll','GetModuleFileNameW'):
        raise ValueError('original image-name import identity changed')
    onexit_scope = bytes.fromhex(re.search(r'const\s+SCOPE\s*:\s*&str\s*=\s*"([0-9a-f]+)"', Path('src/crt_onexit.rs').read_text())[1])
    if mapped(image,0x41b500,len(onexit_scope)) != onexit_scope:
        raise ValueError('onexit scope differs from original PE')
    (out/'onexit-scope.bin').write_bytes(onexit_scope)
    file_regions['onexit-scope'] = sha(onexit_scope)
    caller_source = Path('src/crt_startup_caller.rs').read_text()
    literal = re.search(r'const\s+SCOPE\s*:\s*&str\s*=\s*"([0-9a-f]+)"', caller_source)
    if literal is None:
        raise ValueError('startup caller scope source constant missing')
    raw = bytes.fromhex(literal[1])
    if mapped(image,0x41b238,len(raw)) != raw:
        raise ValueError('startup caller scope bytes differ from unchanged PE')
    (out/'startup-caller-scope.bin').write_bytes(raw)
    file_regions['startup-caller-scope'] = sha(raw)
    for address,name in [(0x4150cc,'IsValidCodePage'),(0x4150d0,'GetACP'),(0x4150d4,'GetOEMCP'),(0x4150d8,'GetCPInfo')]:
        if tuple(import_at_iat(image,address-base)) != ('kernel32.dll',name):
            raise ValueError('locale code-page inventory import changed')
    fls_thunk = mapped(image, 0x408061, 12, executable=True)
    if fls_thunk != bytes.fromhex('8bff558bec5dff25a0504100'):
        raise ValueError('original FLS thunk changed')
    if tuple(import_at_iat(image, 0x4150a0-base)) != ('kernel32.dll', 'FlsGetValue'):
        raise ValueError('original FLS import identity changed; TLS is not equivalent')
    file_regions['ptd-fls-thunk'] = sha(fls_thunk)
    if tuple(import_at_iat(image, 0x4150a4-base)) != ('kernel32.dll', 'FlsSetValue'):
        raise ValueError('original FLS setter import changed')
    for address,name in [(0x4150f8,'GetProcessHeap'),(0x415094,'HeapAlloc')]:
        if tuple(import_at_iat(image,address-base))!=('kernel32.dll',name):
            raise ValueError('heap producer/allocator import changed')
    for name, start, length in [('descriptor_constructor', 0x40be7a, 123), ('descriptor_destructor', 0x40bef5, 53), ('manager', 0x40bf60, 92), ('manager_cleanup', 0x40bfbf, 9)]:
        raw = mapped(image, start, length, executable=True)
        fixture = re.search(r'let\s+'+name+r'\s*:\s*Vec<u8>\s*=\s*"([0-9a-f]+)"', test_source)
        if fixture is None or bytes.fromhex(fixture[1]) != raw:
            raise ValueError('descriptor lifecycle fixture differs from original PE')
        file_regions[name] = sha(raw)
    if tuple(import_at_iat(image, 0x415054-base)) != ('kernel32.dll', 'DeleteCriticalSection'):
        raise ValueError('descriptor destruction import changed')
    for name, start, end in [('file-wrapper', 0x404668, 0x4046a8),
                             ('file-lock', 0x404634, 0x404648),
                             ('file-unlock', 0x404648, 0x40465c),
                             ('file-cleanup', 0x4046ab, 0x4046b7)]:
        raw = mapped(image, start, end-start, executable=True)
        (out/(name+'.bin')).write_bytes(raw)
        file_regions[name] = sha(raw)
    env = dict(os.environ, W2L_EH4_CODE=str(out.resolve()), W2L_EH4_EVIDENCE=str(out.resolve()),
               W2L_EH4_VECTORS=str((observation/'normal-wrapper-vectors.txt').resolve()))
    standard_run = subprocess.run(['cargo','test','--locked','--example','crt_stream',
        'crt_standard_handles_tests'],
        env=env, capture_output=True, timeout=180)
    (out/'standard-handles.stdout').write_bytes(standard_run.stdout)
    (out/'standard-handles.stderr').write_bytes(standard_run.stderr)
    require_test_completions(standard_run, [
        b'crt_standard_handles_tests::original_standard_handles_preserve_inheritance_and_classify_api_results',
        b'crt_standard_handles_tests::original_inherited_records_feed_standard_initialization_with_checked_bounds',
        b'crt_standard_handles_tests::word_compare_and_signed_selection_keep_independent_boundaries',
        b'crt_standard_handles_tests::original_descriptor_construction_connects_inheritance_and_destruction',
        b'crt_standard_handles_tests::original_allocation_manager_scope_orders_lock_publication_and_cleanup',
        b'crt_standard_handles_tests::original_heap_producer_calloc_and_descriptor_constructor_preserve_error_paths',
        b'crt_standard_handles_tests::two_operand_imul_keeps_signed_overflow_unknowns_and_memory_ownership',
        b'crt_standard_handles_tests::original_errno_router_binds_ptd_or_fallback_without_alias_or_lifetime_renewal',
        b'crt_standard_handles_tests::original_calloc_uses_live_heap_without_startup_or_descriptor_authority',
    ])
    abort_run = subprocess.run(['cargo','test','--locked','--example','crt_stream','crt_abort::'],env=env,capture_output=True,timeout=180)
    (out/'abort-components.stdout').write_bytes(abort_run.stdout)
    (out/'abort-components.stderr').write_bytes(abort_run.stderr)
    require_test_completions(abort_run, [b'crt_abort::original_abort_query_caller_preserves_arguments_cleanup_and_prior_effects',b'crt_abort::original_abort_entry_and_query_mutations_reject', b'crt_abort::rotate_cl_preserves_x86_bits_flags_and_rejects_unknown_count', b'crt_abort::original_abort_branches_reject_unknown_stale_and_cross_thread_effects'])
    ptd_run = subprocess.run(['cargo', 'test', '--locked', '--example', 'crt_stream', 'crt_ptd::'],
                             env=env, capture_output=True, timeout=180)
    (out/'ptd-components.stdout').write_bytes(ptd_run.stdout)
    (out/'ptd-components.stderr').write_bytes(ptd_run.stderr)
    require_test_completions(ptd_run, [
        b'crt_ptd::original_ptd_continuation_and_fls_normal_path',
        b'crt_ptd::different_sized_continuations_preserve_words_and_reject_corruption',
        b'crt_ptd::helper_certificates_reject_mutation_and_aliasing',
        b'crt_ptd::fls_context_is_fiber_scoped_and_stale_slots_cannot_rebind_authority',
        b'crt_ptd::original_errno_call_executes_ptd_body_and_preserves_last_error',
        b'crt_ptd::original_lazy_setter_preserves_failure_return_and_success_sentinel',
        b'crt_ptd::fls_mutation_invalidates_errno_and_rejects_stale_setter_before_effects',
        b'crt_ptd::registered_getter_rejects_changed_original_bytes',
    ])
    ucrt_run = subprocess.run(['cargo', 'test', '--locked', '--example', 'crt_stream', 'crt_ucrt_ptd::'],
                              env=env, capture_output=True, timeout=180)
    (out/'ucrt-components.stdout').write_bytes(ucrt_run.stdout)
    (out/'ucrt-components.stderr').write_bytes(ucrt_run.stderr)
    require_test_completions(ucrt_run, [
        b'crt_ucrt_ptd::ucrt_views_preserve_allocation_identity_and_reject_other_layouts',
        b'crt_ucrt_ptd::original_word_stores_preserve_source_flags_and_adjacent_bytes',
        b'crt_ucrt_ptd::ucrt_errno_view_keeps_heap_identity_and_current_publication_authority',
        b'crt_ucrt_ptd::native_free_releases_actual_owned_storage_and_preflights_rejections',
    ])
    locale_run = subprocess.run(['cargo', 'test', '--locked', '--example', 'crt_stream', 'crt_ucrt_locale::'],
                               env=env, capture_output=True, timeout=180)
    (out/'ucrt-locale.stdout').write_bytes(locale_run.stdout)
    (out/'ucrt-locale.stderr').write_bytes(locale_run.stderr)
    require_test_completions(locale_run, [b'crt_ucrt_locale::locked_increment_needs_a_consumer_effect_contract'])
    descriptor_run = subprocess.run(['cargo', 'test', '--locked', '--example', 'crt_stream', 'crt_startup_descriptors::'],
                                   env=env, capture_output=True, timeout=180)
    (out/'startup-descriptor-resources.stdout').write_bytes(descriptor_run.stdout)
    (out/'startup-descriptor-resources.stderr').write_bytes(descriptor_run.stderr)
    require_test_completions(descriptor_run, [b'crt_startup_descriptors::native_descriptor_resources_preserve_partial_construction_and_identity'])
    cxx_run = subprocess.run(['cargo','test','--locked','--example','crt_stream','crt_cxx_'],
                             env=env,capture_output=True,timeout=180)
    (out/'cxx-record-components.stdout').write_bytes(cxx_run.stdout)
    (out/'cxx-record-components.stderr').write_bytes(cxx_run.stderr)
    require_test_completions(cxx_run, [
        b'crt_cxx_ptd::allocated_dispatcher_ptd_cannot_gain_fls_role_by_retagging_or_copying',
        b'crt_cxx_ptd::heap_ptd_views_preserve_aliases_and_expire_with_allocation_or_slot',
        b'crt_cxx_ptd::original_lazy_ptd_setter_publication_and_cleanup_preserve_heap_identity',
        b'crt_cxx_record::owned_cxx_record_keeps_state_metadata_and_continuation_distinct',
        b'crt_cxx_record::common_handler_executes_cached_getter_with_owned_context_and_no_loader_authority',
        b'crt_cxx_record::common_handler_acquires_heap_ptd_through_original_lazy_producer',
    ])
    free_run = subprocess.run(['cargo','test','--locked','--example','crt_stream','crt_heap_free::'],
                              env=env,capture_output=True,timeout=180)
    (out/'heap-free-components.stdout').write_bytes(free_run.stdout)
    (out/'heap-free-components.stderr').write_bytes(free_run.stderr)
    require_test_completions(free_run, [
        b'crt_heap_free::original_free_failure_executes_mapping_and_owned_errno_without_lifetime_claim',
        b'crt_heap_free::failed_free_receipt_cannot_cross_runtime_thread_or_reauthorize_aliases',
        b'crt_heap_free::original_free_rejects_changed_code_and_mapping',
    ])
    unwind_run=subprocess.run(['cargo','test','--locked','--example','crt_stream','original_cxx_unwind_registers_eh4_preserves_pending_action_and_counter_failures'],env=env,capture_output=True,timeout=180)
    (out/'cxx-unwind-native.stdout').write_bytes(unwind_run.stdout)
    (out/'cxx-unwind-native.stderr').write_bytes(unwind_run.stderr)
    if unwind_run.returncode or b'1 passed' not in unwind_run.stdout:
        raise ValueError('C++ registered unwind native cases failed')
    for test in ['allocation_manager_registers_and_retires_original_eh4_under_startup_authority',
                 'inherited_producer_calls_original_manager_with_live_eh4_registration']:
        result = subprocess.run(['cargo','test','--locked','--example','crt_stream',test],
                                env=env, capture_output=True, timeout=180)
        (out/(test+'.stdout')).write_bytes(result.stdout)
        (out/(test+'.stderr')).write_bytes(result.stderr)
        if result.returncode or b'1 passed' not in result.stdout:
            raise ValueError('registered manager component failed: '+test)

    mapping_env = dict(env, W2L_PE_MAPPING_INPUT=str((original/'unwind.exe').resolve()))
    mapping_run = subprocess.run(['cargo', 'test', '--locked', '--example', 'crt_stream',
                                 'crt_module_image::'],
                                env=mapping_env, capture_output=True, timeout=180)
    (out/'pe-mapping.stdout').write_bytes(mapping_run.stdout)
    (out/'pe-mapping.stderr').write_bytes(mapping_run.stderr)
    require_test_completions(mapping_run, [
        b'crt_module_image::pe32_sections_initialize_original_query_without_temporary_module_owner',
        b'crt_module_image::image_file_anchor_keeps_section_identity_and_rejects_alias_and_partial_init',
    ])

    cookie_run = subprocess.run(['cargo', 'test', '--locked', '--example', 'crt_stream',
                                 'canonical_image_cookie_and_original_record_initialization_compose',
                                 '--', '--ignored'], env=mapping_env, capture_output=True, timeout=180)
    (out/'cookie-record.stdout').write_bytes(cookie_run.stdout)
    (out/'cookie-record.stderr').write_bytes(cookie_run.stderr)
    require_test_completions(cookie_run, [
        b'crt_exception_wrapper::normal_tests::canonical_image_cookie_and_original_record_initialization_compose',
    ])

    # The report must execute these named checks itself, rather than counting
    # coverage observed only in a separate aggregate test run.
    for label, selector, names in [
        ('startup-atomics', 'initializing_atomics_require', [b'crt_locale_startup::initializing_atomics_require_effect_binding_and_preserve_identity_flags_and_failure']),
        ('installed-code-pages', 'installed_code_page_catalog', [b'crt_resident_loader::installed_code_page_catalog_is_distinct_from_acp_and_rejects_unmeasured_queries']),
        ('native-uninitialized', 'crt_malloc::', [b'crt_malloc::native_uninitialized_buffer_preserves_unknown_bytes_identity_and_failure_atomicity']),
        ('word-register', 'crt_locale_code_page::', [b'crt_locale_code_page::original_multibyte_graph_has_explicit_api_and_unproved_path_boundaries', b'crt_locale_code_page::word_register_load_and_zero_extension_preserve_knowledge_flags_and_no_authority', b'crt_locale_code_page::original_initializer_call_accounts_for_its_instruction_before_effects', b'crt_locale_code_page::numeric_address_results_drop_authority_preserve_flags_and_reject_erased_reads']),
        ('argv-contract', 'crt_argv::', [b'crt_argv::original_mode_and_argv_prefix_keep_external_effects_unbound', b'crt_argv::image_name_contract_preserves_units_truncation_ownership_and_unknown_tail', b'crt_argv::native_image_name_is_actual_process_acquisition_not_supplied_text', b'crt_argv::process_file_mode_and_nonzero_bool_preserve_unknown_bits_and_lifetimes', b'crt_argv::utf8_queries_preserve_byte_counts_alias_domains_unknowns_and_output_memory', b'crt_argv::utf8_complete_writes_preserve_unknown_tails_and_reject_unsafe_authority', b'crt_argv::memory_setcc_uses_known_flags_and_preserves_adjacent_state']),
        ('onexit-contract', 'crt_onexit::', [b'crt_onexit::original_onexit_routes_tables_and_preserves_explicit_allocation_boundaries', b'crt_onexit::conditional_memory_selection_reads_before_condition_and_preserves_flags', b'crt_onexit::original_memset_matches_independent_byte_oracle_across_paths_and_bounds', b'crt_onexit::repeated_store_needs_its_own_issuer_and_rejects_other_encodings', b'crt_onexit::original_encoding_discards_authority_and_checks_live_pointer_operands']),
        ('x87-contract', 'crt_x87::', [b'crt_x87::fnclex_requires_an_effect_contract_and_rejects_waiting_or_other_forms', b'crt_x87::fnclex_preserves_top_and_unaffected_state_but_forgets_condition_codes', b'crt_x87::fnclex_context_rejects_expiry_cross_thread_fiber_and_rebinding_before_effects', b'crt_x87::native_fnclex_observations_preserve_host_state_and_compare_only_defined_bits', b'crt_x87::fnclex_emission_preserves_integer_state_and_cannot_replay_a_return', b'crt_x87::fp_control_forms_keep_wait_and_store_distinct_and_require_effect_binding', b'crt_x87::owned_fp_wait_store_load_preserves_unknowns_and_failure_order', b'crt_x87::emitted_wait_fault_precedes_store_fault_and_retains_instruction_address', b'crt_x87::native_control_observations_match_owned_clean_effects_without_host_state_leak', b'crt_x87::explicit_initial_fp_policy_produces_only_controls_and_rejects_rebinding']),
        ('environment-snapshot', 'crt_environment_tests::', [b'crt_environment_tests::environment_snapshot_owns_readonly_copies_and_exact_free_lifetimes', b'crt_environment_tests::environment_declaration_and_mapping_failures_do_not_publish_partial_state', b'crt_environment_tests::environment_api_preflights_stack_saved_state_and_matching_free_abi', b'crt_environment_tests::environment_conversion_reacquires_snapshot_and_preserves_unknown_output_on_rejection']),
        ('c-initializer-graph', 'crt_c_initializers::', [b'crt_c_initializers::original_c_array_and_first_prefix_have_explicit_effect_boundaries', b'crt_c_initializers::slist_opaque_initialization_expires_reads_and_protects_state', b'crt_c_initializers::original_thread_locale_query_preserves_memory_and_rejects_unknown_or_stale_inputs', b'crt_c_initializers::original_boolean_helper_preserves_upper_knowledge_flags_and_return_authority', b'crt_c_initializers::environment_prefix_observes_init_flag_and_preserves_prior_callback_failure_effects', b'crt_c_initializers::original_environment_scan_preserves_word_bounds_lifetime_and_failure_progress', b'crt_c_initializers::original_string_copy_exposes_cross_allocation_address_cancellation_without_granting_authority', b'crt_c_initializers::checked_original_copy_binds_live_arguments_and_preserves_partial_effects', b'crt_c_initializers::address_relation_revalidates_call_roots_arguments_and_numeric_operands', b'crt_c_initializers::address_relation_binding_rejects_changed_instruction_operands', b'crt_c_initializers::checked_relation_lowers_unrelated_registers_and_word_load_without_host_pointer_casts', b'crt_c_initializers::post_environment_original_calls_branch_and_return_preserve_failure_boundaries']),
        ('native-file-locks', 'native_file_locks_preserve_distinct_records_and_preflight_rejection', [b'crt_resident_loader::native_file_locks_preserve_distinct_records_and_preflight_rejection']),
        ('native-file-lock-resource', 'native_file_constructor_reservation_is_fallible_and_preallocated_effects_need_no_allocation', [b'crt_resident_loader::native_file_constructor_reservation_is_fallible_and_preallocated_effects_need_no_allocation']),
        ('slist-api', 'opaque_slist_api_preflights_', [b'crt_resident_loader::opaque_slist_api_preflights_abi_lifetimes_and_preserves_void_return']),
        ('startup-caller-graph', 'crt_startup_caller::', [b'crt_startup_caller::original_startup_guard_reads_flag_and_rejects_unproved_thread_branch']),
        ('exit-table-graph', 'crt_exit_tables::', [b'crt_exit_tables::original_exit_tables_bind_complete_calls_and_no_free_effects']),
        ('locale-shared-copy', 'crt_locale_memcpy::', [b'crt_locale_memcpy::scalar_copy_graph_preserves_original_edges_tables_and_rejection_cuts', b'crt_locale_memcpy::bit_test_and_byte_repeat_keep_knowledge_flags_aliases_and_partial_progress', b'crt_locale_memcpy::vector_copy_alignment_and_byte_selection_preserve_unknowns_and_reject_controls']),
        ('repeated-copy', 'crt_repeat_copy::', [b'crt_repeat_copy::repeated_copy_requires_dedicated_effect_and_exact_supported_encoding', b'crt_repeat_copy::repeated_copy_preserves_overlap_knowledge_authority_and_partial_progress', b'crt_repeat_copy::repeated_copy_permission_boundary_retains_progress_without_replaying_completed_words']),
    ]:
        checked = subprocess.run(['cargo','test','--locked','--example','crt_stream',selector],
                                 env=mapping_env,capture_output=True,timeout=180)
        (out/(label+'.stdout')).write_bytes(checked.stdout)
        (out/(label+'.stderr')).write_bytes(checked.stderr)
        require_test_completions(checked,names)

    windows_capacity_observation = (utf8_capacity_observations(out/'original-windows-utf8-capacity.jsonl')
                                    if os.name == 'nt' else None)
    windows_narrow_observation = (narrow_conversion_observations(out/'original-windows-narrow-conversion.jsonl')
                                  if os.name == 'nt' else None)
    windows_image_name_observation = (image_name_observations(out/'original-windows-image-name.jsonl')
                                      if os.name == 'nt' else None)
    alignment_run = subprocess.run(['cargo','test','--locked','--example','crt_stream','aligned_'],
                                   env=mapping_env,capture_output=True,timeout=180)
    (out/'locale-alignment.stdout').write_bytes(alignment_run.stdout)
    (out/'locale-alignment.stderr').write_bytes(alignment_run.stderr)
    require_test_completions(alignment_run, [
        b'crt_locale_startup::original_aligned_frame_keeps_unique_return_authority',
        b'crt_aligned_activation::aligned_prefix_proof_rejects_changed_operations_and_extents',
    ])

    command = ['cargo', 'test', '--locked', '--example', 'crt_stream',
               'original_windows_wrapper_state_matches_native_normal_lifecycle', '--', '--ignored']
    run = subprocess.run(command, env=env, capture_output=True, timeout=180)
    (out/'cargo.stdout').write_bytes(run.stdout)
    (out/'cargo.stderr').write_bytes(run.stderr)
    if run.returncode or b'1 passed' not in run.stdout:
        raise ValueError('original wrapper native comparison test failed; see retained cargo logs')
    scope_command = ['cargo', 'test', '--locked', '--example', 'crt_stream',
                     'crt_exception_wrapper::normal_tests::file_scope_']
    scope_run = subprocess.run(scope_command, env=env, capture_output=True, timeout=180)
    (out/'file-scope-cargo.stdout').write_bytes(scope_run.stdout)
    (out/'file-scope-cargo.stderr').write_bytes(scope_run.stderr)
    if scope_run.returncode or b'3 passed' not in scope_run.stdout:
        raise ValueError('original FILE scope native component checks failed')
    live_command = ['cargo', 'test', '--locked', '--example', 'crt_stream',
                    'live_handler_storage_nested_calls_and_failure_effects_are_coherent']
    live_run = subprocess.run(live_command, env=env, capture_output=True, timeout=180)
    (out/'live-dispatch-cargo.stdout').write_bytes(live_run.stdout)
    (out/'live-dispatch-cargo.stderr').write_bytes(live_run.stderr)
    if live_run.returncode or b'1 passed' not in live_run.stdout:
        raise ValueError('live handler storage native regressions failed')
    owned_run=subprocess.run(['cargo','test','--locked','--example','crt_stream','owned_main_frame_storage_executes_original_filter_and_rejects_other_owners'],env=env,capture_output=True,timeout=180)
    (out/'owned-main-cargo.stdout').write_bytes(owned_run.stdout)
    (out/'owned-main-cargo.stderr').write_bytes(owned_run.stderr)
    if owned_run.returncode or b'1 passed' not in owned_run.stdout: raise ValueError('owned Main live storage checks failed')
    local_run=subprocess.run(['cargo','test','--locked','--example','crt_stream','original_local_store_writes_canonical_owned_storage_in_live_registry_lifetime'],env=env,capture_output=True,timeout=180)
    (out/'owned-local-cargo.stdout').write_bytes(local_run.stdout)
    (out/'owned-local-cargo.stderr').write_bytes(local_run.stderr)
    if local_run.returncode or b'1 passed' not in local_run.stdout: raise ValueError('owned local live write checks failed')
    loop_run=subprocess.run(['cargo','test','--locked','--example','crt_stream','decoded_local_loop_uses_live_storage_and_preserves_callback_failure_effects'],env=env,capture_output=True,timeout=180)
    (out/'owned-loop-cargo.stdout').write_bytes(loop_run.stdout)
    (out/'owned-loop-cargo.stderr').write_bytes(loop_run.stderr)
    if loop_run.returncode or b'1 passed' not in loop_run.stdout: raise ValueError('decoded local loop live storage checks failed')
    edges_run=subprocess.run(['cargo','test','--locked','--example','crt_stream','instruction_path_checks_reject_unknown_flags_and_disagreeing_original_edges'],env=env,capture_output=True,timeout=180)
    (out/'path-edge-cargo.stdout').write_bytes(edges_run.stdout)
    (out/'path-edge-cargo.stderr').write_bytes(edges_run.stderr)
    if edges_run.returncode or b'1 passed' not in edges_run.stdout: raise ValueError('native branch obligation checks failed')
    finally_run=subprocess.run(['cargo','test','--locked','--example','crt_stream','original_finally_dispatch_writes_live_fields_in_instruction_order'],env=env,capture_output=True,timeout=180)
    (out/'live-finally-cargo.stdout').write_bytes(finally_run.stdout)
    (out/'live-finally-cargo.stderr').write_bytes(finally_run.stderr)
    if finally_run.returncode or b'1 passed' not in finally_run.stdout: raise ValueError('original finally live field checks failed')
    cached_unwind=subprocess.run(['cargo','test','--locked','--example','crt_stream','original_cxx_unwind_uses_cached_ptd_getter_without_loader_authority'],env=env,capture_output=True,timeout=180)
    (out/'cxx-cached-unwind.stdout').write_bytes(cached_unwind.stdout)
    (out/'cxx-cached-unwind.stderr').write_bytes(cached_unwind.stderr)
    if cached_unwind.returncode or b'1 passed' not in cached_unwind.stdout:
        raise ValueError('cached C++ unwind integration failed')
    for label, test in [
        ('delivery-children', 'suspended_delivery_lends_only_child_frames_and_rejects_stale_or_parent_authority'),
        ('delivery-cached-unwind', 'original_cached_unwind_executes_under_pending_delivery_child_authority'),
        ('dispatcher-delivery-unwind', 'original_common_dispatcher_calls_registered_unwind_under_pending_delivery'),
        ('prefix-delivery-unwind', 'original_prefix_produces_dispatcher_metadata_under_pending_delivery'),
        ('bound-cxx-invocation', 'original_cxx_invocation_binds_pending_event_and_captured_objects'),
        ('chain-ownership-gap', 'original_cxx_fs_views_do_not_establish_shared_thread_chain_selection'),
        ('shared-chain', 'original_cxx_and_eh4_share_live_lifo_thread_head'),
        ('chain-effect-lifetime', 'shared_chain_rechecks_owner_at_original_fs_effect'),
        ('live-return', 'original_empty_search_executes_guard_and_protected_return'),
        ('ordered-search', 'original_return_receipt_advances_only_matching_live_registration'),
        ('registered-errno', 'original_ucrt_errno_registration_preserves_pending_delivery_ownership'),
        ('abort-locked','original_abort_locked_query_owns_frame_lock_and_failure_effects'),
        ('inline-exit','original_inline_exit_record_preserves_registry_return_and_failure_lifetimes'),
    ]:
        delivery = subprocess.run(['cargo','test','--locked','--example','crt_stream',test],env=env,capture_output=True,timeout=180)
        (out/(label+'.stdout')).write_bytes(delivery.stdout)
        (out/(label+'.stderr')).write_bytes(delivery.stderr)
        require_test_completions(delivery, [('crt_exception_wrapper::normal_tests::'+test).encode()])
    expected = [[w['return_eax'], w['return_flags'], w['caller_stack_delta'], *w['saved']] for w in observed]
    actual = [[int(n) for n in line.split()] for line in (out/'normal-wrapper-results.txt').read_text().splitlines()]
    if actual != expected:
        raise ValueError('native wrapper restoration/result mismatch')
    source_hash = sha((out/'normal-wrapper.rs').read_bytes())
    result = dict(kind='original prolog/epilog component comparison with explicit unexecuted body boundary',
                  windows_image_name_api_observation_sha256=windows_image_name_observation,
                  windows_narrow_conversion_observation_sha256=windows_narrow_observation,
                  windows_utf8_capacity_observation_sha256=windows_capacity_observation,
                  argv_count_vectors=16, argv_count_component_cases=53, argv_count_windows_original_pairs=0,
                  fp_entry_original_boundary_modes=16, fp_entry_FP_state_effects_implemented=["owned FWAIT", "FNSTCW with partial knowledge", "clean-state FLDCW", "known/profile-bound STMXCSR"], fp_original_control_component_modes=18, fp_owned_effect_modes=23, fp_emitted_wait_store_modes=4, fp_initial_state_acquired=False, fp_initial_controls_policy="w2l-win2022-entry-control-027f-mxcsr-1f80-v1", fp_explicit_profile_boundary="0x4109ba original locale initializer composition unbound", fp_entry_boundary="0x40d013 MOVZX rejects unknown original control", fp_new_whole_PE_pairs=0, boolean_helper_component_modes=7, boolean_helper_artifact_modes=7, environment_prefix_component_modes=4, environment_snapshot_runtime_modes=5, environment_declaration_failure_modes=8, environment_api_abi_modes=10, environment_artifact_modes=16, thread_locale_query_component_modes=10, thread_locale_query_production_modes=10, post_argv_original_helper_cases=15, slist_API_ABI_lifetime_cases=11, slist_private_bytes="opaque; old reads expired; raw guest access rejected", slist_new_whole_PE_pairs=0, argv_calloc_component_cases=18, ucrt_errno_field_cases=13, argv_mode1_publication="original native-profile component; no whole PE", argv_calloc_original_windows_pairs=0,
                  native_utf8_write_vectors=7, native_utf8_write_unsafe_modes=10, native_utf8_write_api_modes=6, original_image_write_cases=6*int(sys.platform.startswith("linux")),
                  argv_locale_native_cases=13, argv_narrow_conversion_implemented=False,
                  native_file_mode_contract_tests=1, native_utf8_query_vectors=7, native_utf8_query_api_cases=12, protection_data_word_cases=5,
                  pe_sha256=sha(image), helper_sha256=sha(helper), epilog_sha256=sha(epilog),
                  handler_scope_store_sha256=sha(scope_store),
                  handler_prolog_sha256=sha((out/'handler-prolog.bin').read_bytes()),
                  handler_installer_sha256=sha((out/'handler-installer.bin').read_bytes()),
                  event_normalizer_sha256=sha((out/'event-normalizer.bin').read_bytes()),
                  guard_validator_sha256=sha((out/'original-guard-validator.bin').read_bytes()),
                  security_check_sha256=sha((out/'original-security-check.bin').read_bytes()),
                  scope_header_sha256=sha((out/'file-scope-header.bin').read_bytes()),
                  prefix_sha256=sha((out/'original-handler-prefix.bin').read_bytes()),
                  context_helper_sha256=sha((out/'original-context-check.bin').read_bytes()),
                  filter_bridge_sha256=sha((out/'original-filter-bridge.bin').read_bytes()),
                  main_filter_sha256=sha((out/'main-filter-0.bin').read_bytes()),
                  main_prolog_sha256=sha((out/'main-prolog.bin').read_bytes()),
                  inner_prolog_sha256=sha((out/'Inner-prolog.bin').read_bytes()),
                  main_activation_sha256=sha((out/'main-activate.bin').read_bytes()),
                  main_scope_header_sha256=sha((out/'Main-scope-header.bin').read_bytes()),
                  locale_state_evidence=locale_state_evidence(image),
                  unwind_binding_source_sha256=sha((out/'cxx-unwind-connected.rs').read_bytes()),
                  locale_code_page_declared_cases=18, locale_view_declared_cases=4, locale_prefix_declared_cases=45, initializer_api_new_windows_pairs=0, locale_utf8_initialized_cases=49, locale_result_native_cases=28, startup_scalar_atomic_native_cases=26, locale_result_replay_rejections=28, locale_result_new_windows_pairs=0, locale_shared_new_windows_pairs=0, exit_table_helper_cases=21, exit_table_wrapper_cases=10, exit_table_rollback_cases=2, exit_table_new_windows_pairs=0, onexit_routing_cases=24, onexit_manager_cases=22, argv_api_native_cases=20, argv_mode_cases=5, argv_output_contract_cases=86, argv_negative_output_cases=17, argv_new_whole_pe_pairs=0, conditional_memory_selection_cases=36, onexit_completed_native_registration_component_cases=2, onexit_entry_completed_registrations=1, onexit_memset_byte_oracle_cases=5056, onexit_nonempty_registration_supported=False, onexit_new_windows_pairs=0, c_array_declared_cases=28, c_array_replay_rejections=28, c_array_original_callback_components=16, x87_exhaustive_status_control_cases=262144, x87_partial_knowledge_cases=7, x87_context_modes=11, x87_emission_modes=7, x87_native_instruction_observations=42*int(sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64","amd64")), x87_new_windows_pairs=0, c_initializer_constructor_cases=16, c_array_new_windows_pairs=0, startup_caller_cases=25, startup_caller_replay_rejections=25, startup_caller_new_windows_pairs=0, locale_memcpy_declared_matrix_cases=378, locale_memcpy_knowledge_and_negative_cases=11, bit_test_register_cases=24, bit_test_memory_cases=4, rep_byte_cases=6, vector_memory_cases=9, installed_code_page_contract_cases=15, numeric_address_vectors=21, numeric_stale_vectors=21, numeric_alias_and_unknown_cases=2, initializer_call_budget_cases=2, word_load_cases=40, word_register_extension_cases=112, rep_permission_progress_cases=1, rep_overlap_vectors=7, rep_zero_cursor_cases=3, rep_unknown_knowledge_cases=1, rep_typed_alias_cases=1, rep_partial_failure_modes=10, malloc_declared_cases=18, native_uninitialized_sizes=4, native_uninitialized_failure_modes=10, native_heap_api_modes=5, locale_xadd_vectors=6, aligned_activation_nested_cases=4, aligned_activation_negative_modes=18, aligned_activation_partial_frame_cases=1, aligned_activation_new_windows_pairs=0, startup_entry_cases=9, startup_module_control_cases=9, startup_mapped_resolver_cases=14, resident_load_helper_cases=4, resident_loader_new_windows_pairs=0, startup_process_fls_callback_cases=4, startup_resolver_new_windows_pairs=0, startup_module_new_windows_pairs=0, startup_cpu_feature_cases=15, startup_declared_profile_cases=17, initializer_table_cases=20, startup_lock_loop_cases=14, startup_heap_cases=12, startup_second_fls_cases=15, second_fiber_profile_cases=12, cache_publication_cases=22, native_fls_read_cases=16, startup_ptd_code_mutations=4, ucrt_code_mutations=4, ucrt_layout_cases=21, ucrt_word_store_cases=30, ucrt_new_windows_pairs=0, ucrt_reference_cases=40, ucrt_locale_code_mutations=4, ucrt_locale_new_windows_pairs=0, ucrt_replacement_cases=20, ucrt_replacement_mutations=7, ucrt_replacement_new_windows_pairs=0, startup_descriptor_resource_cases=12, startup_descriptor_code_mutations=7, startup_descriptor_new_windows_pairs=0, native_standard_linux_body_cases=9*int(sys.platform.startswith("linux")), native_standard_new_windows_pairs=0, command_line_body_cases=10, command_line_new_windows_pairs=0, startup_ptd_new_windows_pairs=0, cache_publication_new_windows_pairs=0, startup_second_fls_new_windows_pairs=0, startup_heap_new_windows_pairs=0, startup_lock_new_windows_pairs=0, virtual_protect_native_cases=22, virtual_protect_new_windows_pairs=0, native_fls_producer_cases=10, original_fls_wrapper_fallback_cases=3, startup_constructor_guard_cases=10, startup_declared_profile_new_windows_pairs=0, startup_cpu_native_observation_cases=2*int(sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64","amd64")), startup_cpu_new_windows_pairs=0, startup_cpu_tail_sha256=sha((out/"startup-cpu-tail.bin").read_bytes()), native_cookie_runtime_cycles=int(sys.platform.startswith("linux")), cookie_entropy_native_cases=16, cookie_entropy_api_boundary_cases=9, cookie_entropy_new_windows_pairs=0, cookie_entropy_sha256=sha((out/'cookie-entropy.bin').read_bytes()), cookie_imports=cookie_imports, cookie_record_native_cases=8, cookie_input_class_cases=8, cookie_record_new_windows_pairs=0, cookie_initializer_sha256=sha((out/'cookie-initializer.bin').read_bytes()), pe_mapping_native_cases=31, pe_mapping_recorded_input_queries=1, image_file_anchor_native_cases=20, image_file_anchor_recorded_input_queries=1, pe_mapping_new_windows_pairs=0, inline_exit_native_cases=26, inline_exit_new_windows_pairs=0, abort_branch_native_cases=13, abort_branch_new_windows_pairs=0, abort_locked_native_cases=12, abort_locked_new_windows_pairs=0, rotate_truth_table_cases=35, abort_query_native_cases=8, abort_query_new_windows_pairs=0, registered_errno_native_cases=16, registered_errno_new_windows_pairs=0, heap_free_native_cases=28, heap_free_new_windows_pairs=0, pending_lazy_native_cases=9, pending_lazy_new_windows_pairs=0, lazy_common_handler_native_cases=24, lazy_common_handler_new_windows_pairs=0, heap_ptd_view_native_cases=17, lazy_ptd_native_cases=20, lazy_ptd_new_windows_pairs=0, ordered_search_native_cases=85, unobserved_context_native_cases=27, unobserved_context_new_windows_pairs=0, original_empty_search_native_cases=1, ordered_search_new_windows_pairs=0, shared_chain_native_cases=24, shared_chain_effect_lifetime_cases=4, shared_chain_new_windows_pairs=0, chain_ownership_diagnostic_experiments=1, chain_ownership_new_windows_pairs=0, bound_cxx_invocation_native_cases=34, bound_cxx_invocation_new_windows_pairs=0, prefix_delivery_unwind_native_cases=14, prefix_delivery_new_windows_pairs=0, dispatcher_delivery_unwind_native_cases=8, dispatcher_delivery_new_windows_pairs=0, delivery_child_native_cases=14, delivery_cached_unwind_native_cases=4, delivery_new_windows_pairs=0,
                  unwind_native_cases=24, cached_unwind_native_cases=14, cached_unwind_new_windows_pairs=0, unwind_new_windows_pairs=0, unwind_binding_rust_tests=1,
                  unwind_state_source_sha256=sha((out/'unwind-state-live.rs').read_bytes()),
                  unwind_state_native_cases=12, unwind_state_new_windows_pairs=0,
                  cached_common_source_sha256=sha((out/'cached-common-handler.rs').read_bytes()),
                  cached_common_native_cases=20, cached_common_new_windows_pairs=0,
                  dispatcher_dynamic_source_sha256=sha((out/'dynamic-dispatcher-ptd.rs').read_bytes()),
                  dispatcher_dynamic_native_cases=29, dispatcher_dynamic_new_windows_pairs=0,
                  dynamic_fls_source_sha256=sha((out/'dynamic-fls-component.rs').read_bytes()),
                  dynamic_fls_native_cases=19, dynamic_fls_new_windows_pairs=0,
                  cold_resolver_source_sha256=sha((out/'cold-resolver-component.rs').read_bytes()),
                  cold_resolver_scripted_cases=17, cold_resolver_new_windows_pairs=0,
                  cxx_record_rust_tests=10, cxx_record_new_windows_pairs=0, ptd_component_rust_tests=7, ptd_new_windows_pairs=0, errno_router_component_cases=9, errno_router_new_windows_pairs=0, live_heap_calloc_native_cases=9, heap_calloc_component_cases=13, heap_calloc_new_windows_pairs=0, registered_manager_component_cases=6, registered_manager_new_windows_pairs=0, manager_component_cases=6, manager_new_windows_pairs=0, descriptor_lifecycle_component_cases=4, descriptor_lifecycle_new_windows_pairs=0, inherited_component_cases=7, inherited_new_windows_pairs=0, standard_handle_component_cases=25, standard_handle_new_windows_pairs=0,
                  original_printf_routing_sha256=sha((out/'printf-routing-live.bin').read_bytes()),
                  original_printf_context_sha256=sha((out/'printf-context-live.bin').read_bytes()),
                  original_printf_entry_sha256=sha((out/'printf-entry-live.bin').read_bytes()),
                  main_live_completion_sha256=sha((out/'main-completion-live.bin').read_bytes()),
                  main_live_security_sha256=sha((out/'main-security-live.bin').read_bytes()),
                  main_live_initializer_sha256=sha((out/'main-initial-live.bin').read_bytes()),
                  main_live_fill_sha256=sha((out/'main-fill-live.bin').read_bytes()),
                  landing_pivot_sha256=sha((out/'original-landing-pivot.bin').read_bytes()),
                  restore_sha256=sha((out/'original-restore.bin').read_bytes()),
                  restored_landing_sha256=sha((out/'original-restored-landing.bin').read_bytes()),
                  landing_context_sha256=sha((out/'original-landing-context.bin').read_bytes()),
                  owned_frame_native_cases=202, owned_local_store_cases=10, original_notification_sha256=sha((out/'owned-notification.bin').read_bytes()), owned_local_loop_cases=13, original_cleanup_loop_cases=21, owned_local_body_sha256=sha((out/'owned-local-body.bin').read_bytes()), local_level_store_sha256=sha(local_store), original_cleanup_hashes={name:sha((out/('owned-'+name+'.bin')).read_bytes()) for name in ['CleanupA','CleanupB','CleanupC']},
                  owned_delivery_lifetime_cases=144, cross_frame_delivery_cases=126, connected_cleanup_retirement_cases=111, native_local_stack_cases=111, native_local_loop_cases=111, live_callback_cases=111, conditional_resume_cases=69, post_global_caller_cases=61, opaque_dispatcher_cases=10, selected_bridge_cases=51, landing_pivot_cases=44, landing_context_cases=35, context_transfer_cases=31, restoration_completion_cases=25, initial_raise_rejection_cases=6, main_initialization_rejection_cases=5, main_normal_cpu_binding_cases=18, main_live_return_cases=4, main_live_failure_cases=14, original_printf_return_cases=2, original_printf_failure_cases=6, original_formatter_locale_rejections=1, original_event_return_gate_cases=19, unwind_continuation_input_cut_cases=4, cleanup_continuation_boundary_cases=2,
                  branch_obligation_native_cases=3,
                  ordinary_call_boundary_cases=1,
                  global_wrapper_sha256=sha((out/'global-wrapper.bin').read_bytes()), unwind_caller_sha256=sha((out/'original-unwind-caller.bin').read_bytes()), local_wrapper_sha256=sha((out/'original-local-wrapper.bin').read_bytes()),
                  main_scope_table_sha256=sha((out/'Main-scope-table.bin').read_bytes()),
                  complete_handler_sha256=sha((out/'handler-complete.bin').read_bytes()),
                  observation_sha256=sha((observation/'report.json').read_bytes()),
                  vectors_sha256=sha(vector_bytes), rust_sha256=source_hash, command=command,
                  comparisons=5, whole_pe_translation_pairs=0, environment_scan_native_cases=12, environment_conversion_native_cases=12, environment_table_native_cases=18, environment_table_entry_cases=2, post_environment_continuation_cases=4, original_file_initializer_cases=11, native_file_lock_cases=11, native_file_resource_cases=1, environment_copy_address_cases=6, environment_empty_entry_boundary="0x4109ba original locale initializer composition unbound", environment_checked_copy_cases=8, environment_relation_lifetime_cases=17, environment_independent_word_cases=2, environment_native_free_cases=9, environment_conversion_new_windows_pairs=0, environment_scan_new_windows_pairs=0,
                  live_finally_native_cases=38, live_finally_windows_pairs=0, live_finally_hashes=finally_regions,
                  file_scope_code_sha256=file_regions, file_scope_imports=file_imports,
                  file_scope_native_test_functions=3,
                  live_dispatch_native_cases=37, live_dispatch_windows_original_pairs=0,
                  file_scope_evidence="Native component cases with explicit driver cut; no new Windows differential pairs",
                  scope='Live registry fixture; body EAX/flags inputs; original stack/FS/saved-state restoration only')
    if compare:
        previous = json.loads(compare.read_text())
        if previous['locale_state_evidence'] != result['locale_state_evidence']:
            raise ValueError('wrapper cross-host locale evidence differs')
        for key in ['cookie_entropy_sha256','cookie_imports','cookie_initializer_sha256', 'unwind_binding_source_sha256', 'unwind_state_source_sha256', 'cached_common_source_sha256', 'dispatcher_dynamic_source_sha256', 'dynamic_fls_source_sha256', 'cold_resolver_source_sha256', 'live_finally_hashes', 'original_notification_sha256', 'original_cleanup_hashes', 'owned_local_body_sha256', 'local_level_store_sha256', 'pe_sha256', 'helper_sha256', 'epilog_sha256', 'handler_scope_store_sha256', 'handler_prolog_sha256', 'handler_installer_sha256', 'event_normalizer_sha256', 'guard_validator_sha256', 'security_check_sha256', 'scope_header_sha256', 'prefix_sha256', 'context_helper_sha256', 'filter_bridge_sha256', 'main_filter_sha256', 'main_prolog_sha256', 'inner_prolog_sha256', 'main_activation_sha256', 'main_scope_header_sha256', 'main_scope_table_sha256', 'complete_handler_sha256', 'global_wrapper_sha256', 'observation_sha256', 'vectors_sha256', 'rust_sha256', 'file_scope_code_sha256', 'file_scope_imports']:
            if previous[key] != result[key]:
                raise ValueError('wrapper cross-host provenance differs: '+key)
        result['matching_windows_native_report'] = str(compare)
    result['replay_sources'] = source_guard.verify()
    (out/'report.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ['original', 'observation', 'output']:
        parser.add_argument(name, type=Path)
    parser.add_argument('--compare', type=Path)
    args = parser.parse_args()
    check(args.original, args.observation, args.output, args.compare)
