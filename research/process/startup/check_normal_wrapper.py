"""Compare original observed wrapper boundaries with mechanically emitted slices.

The formatter body is an explicit input boundary (observed EAX/flags). This
does not execute that body, Windows exception dispatch, or a whole PE in Rust.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess

from formatter_binding import mapped, locale_state_evidence
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
    if standard_run.returncode or b'5 passed' not in standard_run.stdout:
        raise ValueError('standard-handle component check failed')
    for test in ['allocation_manager_registers_and_retires_original_eh4_under_startup_authority',
                 'inherited_producer_calls_original_manager_with_live_eh4_registration']:
        result = subprocess.run(['cargo','test','--locked','--example','crt_stream',test],
                                env=env, capture_output=True, timeout=180)
        (out/(test+'.stdout')).write_bytes(result.stdout)
        (out/(test+'.stderr')).write_bytes(result.stderr)
        if result.returncode or b'1 passed' not in result.stdout:
            raise ValueError('registered manager component failed: '+test)

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
                  locale_state_evidence=locale_state_evidence(image),
                  registered_manager_component_cases=6, registered_manager_new_windows_pairs=0, manager_component_cases=6, manager_new_windows_pairs=0, descriptor_lifecycle_component_cases=4, descriptor_lifecycle_new_windows_pairs=0, inherited_component_cases=7, inherited_new_windows_pairs=0, standard_handle_component_cases=25, standard_handle_new_windows_pairs=0,
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
                  comparisons=5, whole_pe_translation_pairs=0,
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
        for key in ['live_finally_hashes', 'original_notification_sha256', 'original_cleanup_hashes', 'owned_local_body_sha256', 'local_level_store_sha256', 'pe_sha256', 'helper_sha256', 'epilog_sha256', 'handler_scope_store_sha256', 'handler_prolog_sha256', 'handler_installer_sha256', 'event_normalizer_sha256', 'guard_validator_sha256', 'security_check_sha256', 'scope_header_sha256', 'prefix_sha256', 'context_helper_sha256', 'filter_bridge_sha256', 'main_filter_sha256', 'main_prolog_sha256', 'inner_prolog_sha256', 'main_activation_sha256', 'main_scope_header_sha256', 'main_scope_table_sha256', 'complete_handler_sha256', 'global_wrapper_sha256', 'observation_sha256', 'vectors_sha256', 'rust_sha256', 'file_scope_code_sha256', 'file_scope_imports']:
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
