"""Check original CRT text/selector instructions against frozen and observed effects.

The entry is an explicitly initialized component state. This does not execute
the original PE entry, formatter, flush/exit path or general CRT startup. Native
backends script API outcomes; they do not reproduce real OS short writes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

from observe_stdio import CASES, parse_events, summarize
from stdio_binding import extract

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(path, limit=4 * 1024 * 1024):
    raw = path.read_bytes()
    if len(raw) > limit:
        raise ValueError('CRT evidence file budget: ' + str(path))
    return json.loads(raw)


def validate_evidence(original, observed):
    """Bind retained artifacts and raw observation receipts before compilation."""
    frozen_raw = (HERE / 'stdio-frozen.json').read_bytes()
    frozen = json.loads(frozen_raw)
    baseline = load(original / 'report.json')
    plan = load(observed / 'plan.json')
    report = load(observed / 'report.json')
    for key, filename in [('pe_sha256', 'unwind.exe'),
                          ('object_sha256', 'unwind.obj'),
                          ('source_sha256', 'unwind_probe.c')]:
        identity = sha((original / filename).read_bytes())
        if plan.get(key) != identity or report.get(key) != identity:
            raise ValueError('CRT observer/original artifact identity: ' + key)
        if key in baseline and baseline[key] != identity:
            raise ValueError('CRT ordinary baseline identity: ' + key)
    if report['source_sha256'] != frozen['artifact']['source_sha256']:
        raise ValueError('CRT authored source differs from frozen source')
    if (report.get('frozen_expectations_sha256') != sha(frozen_raw)
            or plan.get('frozen_expectations_sha256') != sha(frozen_raw)
            or report.get('cases') != CASES or plan.get('cases') != CASES):
        raise ValueError('CRT frozen observer contract changed')
    if report.get('whole_pe_translation_pairs') != 0:
        raise ValueError('CRT component evidence misclassified as whole-PE')
    physical = (original / 'stdout').read_bytes()
    if (sha(physical) != frozen['artifact']['stdout_sha256']
            or physical.hex() != baseline.get('stdout_hex')
            or physical.hex() != plan.get('original_stdout_hex')
            or physical.hex() != report.get('original_stdout_hex')
            or baseline.get('exit') != 0 or baseline.get('stderr_hex') != ''
            or (original / 'stderr').read_bytes()):
        raise ValueError('CRT ordinary baseline bytes/exit differ')
    # The frozen JSON-report source has exactly one terminal newline. This is
    # source input to the text component, not an output inferred from its code.
    if not physical.endswith(b'\r\n') or b'\n' in physical[:-2] or b'\r' in physical[:-2]:
        raise ValueError('CRT frozen report newline grammar')
    logical = physical[:-2] + b'\n'
    if len(logical) != frozen['artifact']['logical_report_characters']:
        raise ValueError('CRT frozen report logical input count')
    runs = report.get('runs', [])
    labels = [row.get('label') for row in runs]
    if labels != [*CASES, 'cleanup-failure']:
        raise ValueError('CRT observer missing/duplicate/reordered evidence')
    checked = []
    for record in runs:
        label = record['label']
        folder = observed / label
        for key, filename in [('observer_stdout_sha256', 'observer.stdout'),
                              ('child_stdout_sha256', 'child.stdout'),
                              ('child_stderr_sha256', 'child.stderr')]:
            if sha((folder / filename).read_bytes()) != record.get(key):
                raise ValueError('CRT raw observer receipt changed: ' + label + '/' + filename)
        cleanup = label == 'cleanup-failure'
        events = parse_events((folder / 'observer.stdout').read_bytes(),
                              'baseline' if cleanup else label, plan, cleanup)
        if events[-1] != record.get('summary') or (folder / 'observer.stderr').read_bytes():
            raise ValueError('CRT observer terminal receipt differs: ' + label)
        if cleanup:
            continue
        observed_result = summarize(events, label, plan)
        if observed_result != record.get('observed'):
            raise ValueError('CRT summarized result differs from raw events: ' + label)
        expected = physical if label == 'baseline' else b''
        if (folder / 'child.stdout').read_bytes() != expected or (folder / 'child.stderr').read_bytes():
            raise ValueError('CRT observer physical output changed: ' + label)
        modules = record.get('modules', [])
        if not any(m.get('sha256') == plan['pe_sha256'] and m.get('machine') == 0x14c
                   for m in modules):
            raise ValueError('CRT observed process lacks exact original x86 image')
        checked.append(observed_result)
    return frozen, report, logical, checked


def expanded(row, key):
    if key + '_hex' in row:
        return bytes.fromhex(row[key + '_hex'])
    runs = row[key + '_runs']
    output = bytearray()
    for encoded, count in runs:
        if type(count) is not int or not 0 <= count <= 16384:
            raise ValueError('CRT frozen byte-run bound')
        output.extend(bytes.fromhex(encoded) * count)
    if len(output) > 32768:
        raise ValueError('CRT frozen expanded byte budget')
    return bytes(output)


RUNNER = r'''
struct Script { responses:Vec<CrtWriteResult>, requests:Vec<Vec<u8>> }
impl CrtBackend for Script {
 fn write_once(&mut self,_:CrtDescriptorId,bytes:&[u8])->Result<CrtWriteResult,&'static str>{
  let index=self.requests.len();self.requests.push(bytes.to_vec());
  self.responses.get(index).copied().ok_or("unexpected additional API call")
 }
}
fn main(){
 let args:Vec<_>=std::env::args().collect();assert!(args.len()==3||args.len()==4);
 let input=std::fs::read(&args[1]).unwrap();
 let raw=std::fs::read_to_string(&args[2]).unwrap();
 let responses=raw.lines().map(|line|{let n:Vec<u32>=line.split_whitespace().map(|v|v.parse().unwrap()).collect();assert_eq!(n.len(),3);assert!(n[0]<=1);CrtWriteResult{success:n[0]!=0,written:n[1],last_error:if n[0]==0{Some(n[2])}else{None}}}).collect::<Vec<_>>();
 if args.len()==4{
  assert_eq!(args[3],"reject-bound");let mut script=Script{responses,requests:vec![]};
  assert!(matches!(run_crt_text(&input,&mut script),Err("CRT certified input bound")));
  assert!(matches!(run_crt_write(&input,&mut script),Err("CRT worker certified complete source bound")));
  assert!(script.requests.is_empty(),"rejected input reached backend");
  println!("{{\"entry_invocations\":2,\"rejected_entries\":2,\"backend_calls\":0}}");return;
 }
 let mut script=Script{responses:responses.clone(),requests:vec![]};
 let result=run_crt_text(&input,&mut script).unwrap();
 assert_eq!(script.requests.len(),script.responses.len(),"scripted effects not consumed exactly");
 let mut selected=Script{responses,requests:vec![]};
 let write=run_crt_write(&input,&mut selected).unwrap();
 assert_eq!(selected.requests.len(),selected.responses.len(),"selected effects not consumed exactly");
 assert_eq!(selected.requests,script.requests,"selected and direct text effects differ");
 let requests=script.requests.iter().map(|r|format!("\"{}\"",r.iter().map(|v|format!("{v:02x}")).collect::<String>())).collect::<Vec<_>>().join(",");
 println!("{{\"worker\":{:?},\"logical\":{},\"context\":{:?},\"requests\":[{}],\"calls_per_entry\":{},\"entry_invocations\":2}}",result,write.logical,write.context,requests,script.requests.len());
}
'''


def command(args, folder, stem, timeout):
    try:
        result = subprocess.run(args, cwd=ROOT, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        (folder / (stem + '.stdout')).write_bytes(error.stdout or b'')
        (folder / (stem + '.stderr')).write_bytes(error.stderr or b'')
        (folder / (stem + '.failure.json')).write_text(json.dumps(dict(
            timeout_seconds=timeout, command=[str(v) for v in args])) + '\n')
        raise
    (folder / (stem + '.stdout')).write_bytes(result.stdout)
    (folder / (stem + '.stderr')).write_bytes(result.stderr)
    if result.returncode:
        raise ValueError('CRT command failed: ' + stem)
    return result.stdout


def require_cross_host(prior, current):
    if {prior.get('system'), current.get('system')} != {'Windows', 'Linux'}:
        raise ValueError('CRT cross-host gate requires recorded Windows and Linux executions')
    for field in ['pe_sha256', 'object_sha256', 'source_sha256', 'frozen_expectations_sha256',
                  'emitted_rust_sha256', 'native_runner_source_sha256', 'counts', 'results',
                  'supplemental_results']:
        if prior.get(field) != current[field]:
            raise ValueError('CRT cross-host comparison differs: ' + field)


def run(original, observed, output, compare=None):
    frozen, observer, logical, observed_rows = validate_evidence(original, observed)
    output.mkdir(parents=True, exist_ok=False)
    binding = extract(original, output / 'binding')
    source = output / 'text.rs'
    command(['cargo', 'run', '--locked', '--quiet', '--example', 'crt_stream', '--', '--emit-worker',
             str(output / 'binding'), str(source)], output, 'conversion', 180)
    # Determinism is checked without reusing the first generated source file.
    repeat = output / 'text-repeat.rs'
    command(['cargo', 'run', '--locked', '--quiet', '--example', 'crt_stream', '--', '--emit-worker',
             str(output / 'binding'), str(repeat)], output, 'repeat-conversion', 180)
    if source.read_bytes() != repeat.read_bytes():
        raise ValueError('CRT repeated conversion is not deterministic')
    native_source = output / 'native.rs'
    native_source.write_bytes(source.read_bytes() + RUNNER.encode('ascii'))
    binary = output / ('native.exe' if os.name == 'nt' else 'native')
    command(['rustc', '--edition=2021', '-Awarnings', str(native_source), '-o', str(binary)],
            output, 'rustc', 180)
    cases = []
    for row in frozen['writer_cases']:
        if 'request_hex' in row:
            requests = [bytes.fromhex(raw) for raw in row['request_hex']]
        else:
            requests = [expanded({'request_runs': runs}, 'request') for runs in row['request_runs']]
        cases.append(dict(id=row['id'], category='independent frozen scripted vector',
                          data=expanded(row, 'input'), responses=row['responses'],
                          requests=requests, worker=row['worker'], logical=row['logical_u32'],
                          context=[19 if row['errno'] == 'unchanged' else row['errno'],
                                   0 if row['errno'] == 'unchanged' else 1,
                                   23 if row['doserrno'] == 'unchanged' else row['doserrno'],
                                   0 if row['doserrno'] == 'unchanged' else 1]))
    for row, prediction in zip(observed_rows, frozen['windows_observer_cases'], strict=True):
        failed = row['label'] == 'invalid-handle'
        cases.append(dict(id='observed-' + row['label'],
                          category='native projection of instrumented Windows ' + row['api_class'],
                          data=logical, responses=[dict(ok=not failed, written=row['api_count'], error=6)],
                          requests=[bytes.fromhex(observer['original_stdout_hex'])], worker=row['text_result'],
                          logical=row['logical_return'],
                          context=[prediction.get('errno', 19), int('errno' in prediction),
                                   prediction.get('doserrno', 23), int('doserrno' in prediction)],
                          observed_fields=['worker', 'logical'], predicted_only_fields=['context']))
    # Supplemental limits are independent arithmetic, not changes to frozen
    # Windows expectations: each 2560 LF source bytes produce a 5120-byte chunk;
    # 16384 = 6*2560 + 1024. Both component entry bounds are checked separately.
    maximum_requests = [b'\r\n' * 2560] * 6 + [b'\r\n' * 1024]
    supplemental = [
        dict(id='boundary-empty', data=b'', responses=[], requests=[], worker=[0, 0, 0],
             logical=0, context=[19, 0, 23, 0]),
        dict(id='boundary-maximum-lf-expansion', data=b'\n' * 16384,
             responses=[dict(ok=True, written=n) for n in [5120] * 6 + [2048]],
             requests=maximum_requests, worker=[0, 32768, 16384], logical=16384,
             context=[19, 0, 23, 0]),
        dict(id='boundary-over-limit', data=b'\n' * 16385, responses=[], reject=True),
    ]
    for case in supplemental:
        case.update(category='supplemental native boundary; no Windows observation', supplemental=True)
    results, supplemental_results = [], []
    for case in cases + supplemental:
        folder = output / case['id']
        folder.mkdir()
        (folder / 'input').write_bytes(case['data'])
        # Failed API counts are deliberately unavailable sentinel bits. Original
        # control must obtain GetLastError and never consume this output count.
        script = ''.join(f"{int(r['ok'])} {r['written'] if r['ok'] else 4294967295} {r.get('error', 0)}\n"
                         for r in case['responses'])
        (folder / 'responses.txt').write_text(script)
        invocation = [str(binary), str(folder / 'input'), str(folder / 'responses.txt')]
        if case.get('reject'):
            invocation.append('reject-bound')
        stdout = command(invocation,
                         folder, 'native', 20)
        actual = json.loads(stdout)
        if case.get('reject'):
            expected = dict(entry_invocations=2, rejected_entries=2, backend_calls=0)
        else:
            expected = dict(worker=case['worker'], logical=case['logical'], context=case['context'],
                            requests=[b.hex() for b in case['requests']],
                            calls_per_entry=len(case['responses']), entry_invocations=2)
        if actual != expected or (folder / 'native.stderr').read_bytes():
            raise ValueError('CRT native original text effects differ: ' + case['id'])
        destination = supplemental_results if case.get('supplemental') else results
        destination.append(dict(id=case['id'], category=case['category'], input_sha256=sha(case['data']),
                            expected=expected, actual=actual, native_exit=0, native_stderr_hex='',
                            observed_fields=case.get('observed_fields', []),
                            predicted_only_fields=case.get('predicted_only_fields',
                                ['entry_invocations', 'rejected_entries', 'backend_calls'] if case.get('reject')
                                else ['worker', 'logical', 'context'])))
    report = dict(schema=1, kind='original CRT text and selected-write component comparisons; no whole-PE admission',
                  system=platform.system(), platform=platform.platform(), pe_sha256=binding['pe_sha256'],
                  object_sha256=binding['object_sha256'], source_sha256=observer['source_sha256'],
                  frozen_expectations_sha256=observer['frozen_expectations_sha256'],
                  emitted_rust_sha256=sha(source.read_bytes()),
                  native_runner_source_sha256=sha(native_source.read_bytes()),
                  native_binary_sha256=sha(binary.read_bytes()),
                  observer_report_sha256=sha((observed / 'report.json').read_bytes()),
                  counts=dict(independent_scripted_writer_vectors=len(frozen['writer_cases']),
                              unique_input_scenarios=len(cases), native_component_entry_invocations=2 * len(cases),
                              observed_original_text_projections=len(observed_rows),
                              observed_original_logical_projections=len(observed_rows),
                              original_real_api_cases=1, original_scripted_success_cases=3,
                              original_scripted_handle_real_failure_cases=1,
                              supplemental_native_boundary_cases=len(supplemental_results),
                              supplemental_native_entry_invocations=2 * len(supplemental_results),
                              supplemental_rejected_entries=2,
                              whole_pe_translation_pairs=0), results=results,
                  supplemental_results=supplemental_results,
                  limitations=[
                      'Original text-writer and selected-write graphs plus error-map/context effects are emitted at declared component entries.',
                      'PTD context error words are frozen independent predictions, not values measured by the original Windows observer.',
                      'FILE flush, formatter and startup/exit composition are not claimed by this gate.',
                      'All native API providers here are scripts; original Windows observer classes remain separately labelled.',
                      'Two component entries run for each of 21 unique cases; five project one fixed original payload, and sixteen vectors have no new Windows execution.',
                      'Three supplemental empty/maximum-LF/over-limit cases are separately counted; they add no Windows observations.',
                      'Caller supplies initialized owned component state; no ordinary CRT, rcedit or whole-PE compatibility follows.'])
    if compare is not None:
        prior = load(compare)
        require_cross_host(prior, report)
        report['cross_host_report_sha256'] = sha(compare.read_bytes())
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(pe_sha256=report['pe_sha256'], **report['counts'])))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path)
    parser.add_argument('observed', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--compare', type=Path)
    args = parser.parse_args()
    run(args.original.resolve(), args.observed.resolve(), args.output.resolve(), args.compare)
