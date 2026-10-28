"""Compare original observed wrapper boundaries with mechanically emitted slices.

The formatter body is an explicit input boundary (observed EAX/flags). This
does not execute that body, Windows exception dispatch, or a whole PE in Rust.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

from formatter_binding import mapped
from coff_binding import import_at_iat, pe_sections
from observe_stdio import CASES, parse_events, summarize


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


def check(original, observation, out, compare=None):
    out.mkdir(parents=True, exist_ok=False)
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
    helper = mapped(image, 0x401e60, 69, executable=True)
    epilog = mapped(image, 0x404696, 18, executable=True)
    (out/'helper.bin').write_bytes(helper)
    (out/'epilog.bin').write_bytes(epilog)
    scope_store = mapped(image, 0x402355, 3, executable=True)
    (out/'handler-scope-store.bin').write_bytes(scope_store)
    (out/'handler-prolog.bin').write_bytes(mapped(image, 0x402210, 6, executable=True))
    (out/'handler-installer.bin').write_bytes(mapped(image, 0x402263, 15, executable=True))
    (out/'event-normalizer.bin').write_bytes(mapped(image, 0x414a1b, 119, executable=True))
    (out/'original-guard-validator.bin').write_bytes(mapped(image, 0x4021d0, 50, executable=True))
    (out/'original-security-check.bin').write_bytes(mapped(image, 0x40154c, 14, executable=True))
    (out/'file-scope-header.bin').write_bytes(mapped(image, 0x41b400, 16))
    (out/'original-handler-prefix.bin').write_bytes(mapped(image, 0x402210, 98, executable=True))
    (out/'original-context-check.bin').write_bytes(mapped(image, 0x402877, 48, executable=True))
    (out/'original-filter-bridge.bin').write_bytes(mapped(image, 0x402800, 23, executable=True))
    (out/'main-filter-0.bin').write_bytes(mapped(image, 0x401333, 41, executable=True))
    (out/'main-prolog.bin').write_bytes(mapped(image, 0x401280, 54, executable=True))
    (out/'Inner-prolog.bin').write_bytes(mapped(image, 0x4010c0, 48, executable=True))
    (out/'main-activate.bin').write_bytes(mapped(image, 0x40130f, 7, executable=True))
    (out/'Main-scope-header.bin').write_bytes(mapped(image, 0x41b218, 16))
    (out/'Main-scope-table.bin').write_bytes(mapped(image, 0x41b218, 28))
    (out/'handler-complete.bin').write_bytes(mapped(image, 0x402210, 350, executable=True))
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
    file_regions = {}
    for name, start, end in [('file-wrapper', 0x404668, 0x4046a8),
                             ('file-lock', 0x404634, 0x404648),
                             ('file-unlock', 0x404648, 0x40465c),
                             ('file-cleanup', 0x4046ab, 0x4046b7)]:
        raw = mapped(image, start, end-start, executable=True)
        (out/(name+'.bin')).write_bytes(raw)
        file_regions[name] = sha(raw)
    env = dict(os.environ, W2L_EH4_CODE=str(out.resolve()), W2L_EH4_EVIDENCE=str(out.resolve()),
               W2L_EH4_VECTORS=str((observation/'normal-wrapper-vectors.txt').resolve()))
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
    edges_run=subprocess.run(['cargo','test','--locked','--example','crt_stream','instruction_path_checks_reject_unknown_flags_and_disagreeing_original_edges'],env=env,capture_output=True,timeout=180)
    (out/'path-edge-cargo.stdout').write_bytes(edges_run.stdout)
    (out/'path-edge-cargo.stderr').write_bytes(edges_run.stderr)
    if edges_run.returncode or b'1 passed' not in edges_run.stdout: raise ValueError('native branch obligation checks failed')
    expected = [[w['return_eax'], w['return_flags'], w['caller_stack_delta'], *w['saved']] for w in observed]
    actual = [[int(n) for n in line.split()] for line in (out/'normal-wrapper-results.txt').read_text().splitlines()]
    if actual != expected:
        raise ValueError('native wrapper restoration/result mismatch')
    source_hash = sha((out/'normal-wrapper.rs').read_bytes())
    result = dict(kind='original prolog/epilog component comparison with explicit unexecuted body boundary',
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
                  owned_frame_native_cases=42,
                  branch_obligation_native_cases=3,
                  main_scope_table_sha256=sha((out/'Main-scope-table.bin').read_bytes()),
                  complete_handler_sha256=sha((out/'handler-complete.bin').read_bytes()),
                  observation_sha256=sha((observation/'report.json').read_bytes()),
                  vectors_sha256=sha(vector_bytes), rust_sha256=source_hash, command=command,
                  comparisons=5, whole_pe_translation_pairs=0,
                  file_scope_code_sha256=file_regions, file_scope_imports=file_imports,
                  file_scope_native_test_functions=3,
                  live_dispatch_native_cases=37, live_dispatch_windows_original_pairs=0,
                  file_scope_evidence="Native component cases with explicit driver cut; no new Windows differential pairs",
                  scope='Live registry fixture; body EAX/flags inputs; original stack/FS/saved-state restoration only')
    if compare:
        previous = json.loads(compare.read_text())
        for key in ['pe_sha256', 'helper_sha256', 'epilog_sha256', 'handler_scope_store_sha256', 'handler_prolog_sha256', 'handler_installer_sha256', 'event_normalizer_sha256', 'guard_validator_sha256', 'security_check_sha256', 'scope_header_sha256', 'prefix_sha256', 'context_helper_sha256', 'filter_bridge_sha256', 'main_filter_sha256', 'main_prolog_sha256', 'inner_prolog_sha256', 'main_activation_sha256', 'main_scope_header_sha256', 'main_scope_table_sha256', 'complete_handler_sha256', 'observation_sha256', 'vectors_sha256', 'rust_sha256', 'file_scope_code_sha256', 'file_scope_imports']:
            if previous[key] != result[key]:
                raise ValueError('wrapper cross-host provenance differs: '+key)
        result['matching_windows_native_report'] = str(compare)
    (out/'report.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ['original', 'observation', 'output']:
        parser.add_argument(name, type=Path)
    parser.add_argument('--compare', type=Path)
    args = parser.parse_args()
    check(args.original, args.observation, args.output, args.compare)
