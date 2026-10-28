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
    env = dict(os.environ, W2L_EH4_CODE=str(out.resolve()), W2L_EH4_EVIDENCE=str(out.resolve()),
               W2L_EH4_VECTORS=str((observation/'normal-wrapper-vectors.txt').resolve()))
    command = ['cargo', 'test', '--locked', '--example', 'crt_stream',
               'original_windows_wrapper_state_matches_native_normal_lifecycle', '--', '--ignored']
    run = subprocess.run(command, env=env, capture_output=True, timeout=180)
    (out/'cargo.stdout').write_bytes(run.stdout)
    (out/'cargo.stderr').write_bytes(run.stderr)
    if run.returncode or b'1 passed' not in run.stdout:
        raise ValueError('original wrapper native comparison test failed; see retained cargo logs')
    expected = [[w['return_eax'], w['return_flags'], w['caller_stack_delta'], *w['saved']] for w in observed]
    actual = [[int(n) for n in line.split()] for line in (out/'normal-wrapper-results.txt').read_text().splitlines()]
    if actual != expected:
        raise ValueError('native wrapper restoration/result mismatch')
    source_hash = sha((out/'normal-wrapper.rs').read_bytes())
    result = dict(kind='original prolog/epilog component comparison with explicit unexecuted body boundary',
                  pe_sha256=sha(image), helper_sha256=sha(helper), epilog_sha256=sha(epilog),
                  observation_sha256=sha((observation/'report.json').read_bytes()),
                  vectors_sha256=sha(vector_bytes), rust_sha256=source_hash, command=command,
                  comparisons=5, whole_pe_translation_pairs=0,
                  scope='Live registry fixture; body EAX/flags inputs; original stack/FS/saved-state restoration only')
    if compare:
        previous = json.loads(compare.read_text())
        for key in ['pe_sha256', 'helper_sha256', 'epilog_sha256', 'observation_sha256', 'vectors_sha256', 'rust_sha256']:
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
