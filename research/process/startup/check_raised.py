"""Original imported RaiseException invocation composition evidence.

This is not whole-PE admission. Incoming Windows delivery and the closed
RtlUnwind domain remain external contracts. Native execution counts are absent
until a generated program has actually run; prepare/compile never imply them.
"""
import argparse
import json
import os
import platform
import sys
from pathlib import Path
import shutil
import struct

from check_connected import prepare as prepare_connected
from check_frame import command,sha,execute,require_cross_host_result
from frame_binding import frame_evidence
from inventory import mapped_bytes

from check_dispatched import prepare as prepare_dispatch, mutation_directories as dispatch_mutations
from check_dispatched import REJECTION_NAMES as DISPATCH_REJECTIONS

REJECTION_NAMES=DISPATCH_REJECTIONS+('raised-noncontinuable-flags','raised-parameter-count','raised-argument-pointer')
RUNTIME_REJECTIONS=7


def prepare(original,out):
    info=prepare_dispatch(original,out)
    evidence=frame_evidence(original)
    inner=next(frame for frame in evidence['frames'] if frame['symbol']=='_Inner')
    call=inner['blocked_calls'][0]
    if call.get('import')!=['kernel32.dll','RaiseException']:
        raise ValueError('original invocation is not bound RaiseException')
    blocks={b['name']:b for b in evidence['fragments']}
    rows=blocks['Inner-initialize']['instructions']
    pushes=rows[-4:]
    values=[]
    for row in pushes:
        raw=bytes.fromhex(row['code_hex'])
        if len(raw)==2 and raw[0]==0x6a:values.append(struct.unpack('<b',raw[1:])[0]&0xffffffff)
        elif len(raw)==5 and raw[0]==0x68:values.append(struct.unpack('<I',raw[1:])[0])
        else:raise ValueError('original invocation needs four immediate argument pushes')
    code,flags,count,pointer=reversed(values)
    if (code,flags,count,pointer)!=(0xe0424242,0,0,0):
        raise ValueError('frozen source invocation differs from independent exception class')
    rawcall=(out/'Inner-call.bin').read_bytes()
    if len(rawcall)!=6 or rawcall[:2]!=b'\xff\x15' or struct.unpack('<I',rawcall[2:])[0]!=info['raise_exception_iat_va']:
        raise ValueError('original invocation IAT bytes differ')
    original_call=info['original_calls'][-1]
    if pushes[-1]['rva']+pushes[-1]['size']!=original_call['rva']:
        raise ValueError('argument pushes are not contiguous with original call')
    manifest=out/'frame.manifest'
    manifest.write_text(manifest.read_text()+'raised-event\n')
    info['historical_dispatch_delivery_boundary']=info.pop('cuts')
    info['raise_import_identity_premise']='Checker independently binds the original PE import descriptor/thunk to kernel32.dll!RaiseException. The numeric component IAT address alone is not an internal production PE import certificate.'
    info['raise_call']=dict(rva=original_call['rva'],size=len(rawcall),sha256=sha(rawcall),
        iat_va=info['raise_exception_iat_va'],arguments=[code,flags,count,pointer],
        normal_return_rva=original_call['rva']+len(rawcall),
        expected_normal_return_taken=False,
        provenance='Original imported CALL and contiguous pushes; frozen source abandoned-fallthrough expectation zero')
    info['cuts']=[
        info['raise_import_identity_premise'],
        'Raised-event component invokes the original imported instruction in its reviewed bounded exception class; no caller-supplied raw CONTEXT array or handler-stack pointer.',
        'Incoming host/Windows loader state and ordinary CRT startup remain outside admission.',
        'Exception-captured state stays opaque except fields justified by the reviewed valid-stack contract; no equality to original call-site register snapshot is asserted.',
        'RtlUnwind remains a closed application-registration contract; arbitrary secondary/collided exceptions and whole-PE conversion remain rejected.']
    info['evidence_stage']='prepared original invocation only; no new native execution claim'
    (out/'raised-input-provenance.json').write_text(json.dumps(info,indent=2)+'\n')
    return info


def mutation_directories(out):
    results=dispatch_mutations(out)
    tail=bytes.fromhex('6a006a006a0068424242e0')
    for name,offset,value in [('raised-noncontinuable-flags',5,1),
                              ('raised-parameter-count',3,1),('raised-argument-pointer',1,4)]:
        directory=out/'negative'/name;directory.mkdir(parents=True,exist_ok=False)
        for path in out.iterdir():
            if path.is_file() and (path.suffix=='.bin' or path.name=='frame.manifest'):
                shutil.copyfile(path,directory/path.name)
        path=directory/'Inner-prefix.bin';raw=path.read_bytes()
        if raw.count(tail)!=1:raise ValueError('raised mutation lacks unique original arguments')
        changed=bytearray(tail);changed[offset]=value;path.write_bytes(raw.replace(tail,changed,1))
        results.append((name,directory))
    return results


def check_compile(compiler,out):
    source=out/'raised.rs';repeat=out/'raised-repeat.rs'
    command([compiler,out,source],'conversion',out,120)
    command([compiler,out,repeat],'repeat-conversion',out,120)
    if source.read_bytes()!=repeat.read_bytes():raise ValueError('dispatcher emission is nondeterministic')
    negatives=[]
    for name,directory in mutation_directories(out):
        result=command([compiler,directory,directory/'rejected.rs'],name,directory,120,False)
        diagnostic=result.stderr.decode(errors='replace').strip()
        if result.returncode==0 or not diagnostic or 'panicked' in diagnostic:
            raise ValueError('unsafe dispatcher mutation did not reject safely: '+name)
        negatives.append(dict(case=name,exit=result.returncode,diagnostic=diagnostic))
    report=dict(stage='compiled component source, not executed',rust_sha256=sha(source.read_bytes()),
        deterministic_repeat=True,rejections=negatives,whole_pe_translation_pairs=0)
    (out/'raised-compile-report.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def windows_reference(original,out,required):
    directory=original/'raised-native-windows'
    if directory.resolve()==out.resolve():
        if required:raise ValueError('Windows evidence cannot be the current output')
        return None
    if not (directory/'native-raised-report.json').is_file():
        if required:raise ValueError('required retained Windows raised component is missing')
        return None
    return directory


def verify_windows_component(directory,info,local_rust=None,local_harness=None):
    prior=json.loads((directory/'native-raised-report.json').read_text())
    for key in ['pe_sha256','source_sha256','object_sha256']:
        if prior.get(key)!=info[key]:raise ValueError('Windows raised original identity mismatch: '+key)
    source=(directory/'raised.rs').read_bytes()
    harness=(directory/'native-raised.rs').read_bytes()
    harness_lf=harness.replace(b'\r\n',b'\n')
    launch=json.loads((directory/'native-launch/launch.json').read_text())
    if (sha(source)!=prior.get('rust_sha256')
            or sha(harness)!=prior.get('harness_sha256')
            or sha(harness_lf)!=prior.get('harness_lf_sha256')
            or prior.get('native_os')!='nt' or prior.get('whole_pe_translation_pairs')!=0
            or launch.get('stage')!='finished' or launch.get('timeout') is not False
            or launch.get('exit')!=0 or 'failure' in launch
            or launch.get('stdout_hex')!='' or launch.get('stderr_hex')!=''
            or sha((directory/'native-launch/program.bin').read_bytes())!=prior.get('native_sha256')
            or launch.get('executed_sha256')!=prior.get('native_sha256')):
        raise ValueError('Windows raised files/launch provenance failed')
    if (prior.get('native_feature_selector_cases')!=12 or prior.get('native_trace_cases')!=3
            or prior.get('native_runtime_rejections')!=RUNTIME_REJECTIONS
            or tuple(r.get('case') for r in prior.get('rejection_cases',[]))!=REJECTION_NAMES
            or any(type(r.get('exit')) is not int or r['exit']==0 or not r.get('diagnostic')
                   or 'panicked' in r['diagnostic'] for r in prior.get('rejection_cases',[]))):
        raise ValueError('Windows raised conformance inventory differs')
    if local_rust is None:return None
    if source!=local_rust:raise ValueError('Windows/Linux raised Rust differs')
    if local_harness is None or harness_lf!=local_harness.replace(b'\r\n',b'\n'):
        raise ValueError('Windows/Linux raised harness or input expectations differ')
    return dict(cross_host_rust_identical=True,cross_host_same_original_pe=True,cross_host_harness_identical=True,
        native_windows_component_cases=15,
        native_windows_report_sha256=sha((directory/'native-raised-report.json').read_bytes()))



def check(original,compiler,out,require_windows_component=False):
    windows=windows_reference(original,out,require_windows_component)
    out.mkdir(parents=True,exist_ok=False)
    info=prepare(original,out)
    if windows is not None:verify_windows_component(windows,info)
    compiled=check_compile(compiler,out)
    source=out/'raised.rs'
    expected=info['windows_observed']
    globals_expected=','.join(f"Some({g['expected']}u32)" for g in info['globals'])
    target=info['restore_target_va']
    stub=info['image_base']+info['connected_helpers']['context_selector']['comparison_stub_rva']
    inner_local,inner_cursor=info['owner_offsets']['_Inner']
    outer_local,outer_cursor=info['owner_offsets']['_Outer']
    module=info['module_mapping']
    notification_expected=','.join(f'({address}u32,{kind}u32,{value}u32)' for address,kind,value in info['expected_notification_writes'])
    harness=f'''
fn main() {{
 // Independent original instruction arithmetic: push EBP (4), four record
 // words (16), ADD ESP,-764, four saved words (16): frame SP=entry-800.
 for feature in [i32::MIN,-1,0,1,2,i32::MAX] {{
  for selector in [{stub}u32,0u32] {{
   let entry_sp=0x100000u32;
   let o=run_raised(entry_sp,0x13579bdf,feature,0,0xf0000,0x110000,selector).unwrap();
   assert_eq!(o.trace,{expected['trace']});assert_eq!(o.globals,vec![{globals_expected}]);
   assert_eq!(o.notification_writes,vec![{notification_expected}]);
   assert_eq!(o.linked_registrations,vec![true,false,false]);
   let field=|frame:usize,offset:i32|o.frame_words[frame][o.offsets[frame].iter().position(|&at|at==offset).unwrap()];
   assert_eq!(field(0,{info['selected_local_offset']}),Some({expected['selected']}));
   assert_eq!(field(1,{outer_local}),Some({expected['outer']}));assert_eq!(field(2,{inner_local}),Some({expected['inner']}));
   assert_eq!(field(1,{outer_cursor}),Some(u32::MAX));assert_eq!(field(2,{inner_cursor}),Some(u32::MAX));
   assert_eq!(field(0,-752),Some(1)); // Original selected-handler handled store.
   assert_eq!(field(0,-756),Some(77));assert_eq!(field(0,-760),Some(entry_sp-800));assert_eq!(field(0,-764),Some(entry_sp-4));
   assert_eq!(o.cursors,vec![None,Some(-1),Some(-1)]);assert_eq!(o.live,vec![true,false,false]);
   assert_eq!(o.selected_frame,0);assert_eq!(o.selected_target,{info['selection_target_va']});
   for index in [1usize,2,3,6,7,9] {{assert_eq!(o.restored[index],None);}}
   assert_eq!(o.restored[0],Some(77));assert_eq!(o.restored[4],Some(entry_sp-800));assert_eq!(o.restored[5],Some(entry_sp-4));assert_eq!(o.restored[8],Some({target}));
  }}
 }}
 for (initial,expected_trace) in [(1u32,4387u32),(1048576,291),(u32::MAX,4294963491)] {{
  let o=run_raised(0x200000,0x2468ace0,0,initial,0x1f0000,0x210000,0).unwrap();assert_eq!(o.trace,expected_trace);
  for index in [1usize,2,3,6,7,9] {{assert_eq!(o.restored[index],None);}}
  assert_eq!(o.restored[4],Some(0x200000-800));assert_eq!(o.restored[5],Some(0x200000-4));
  assert_eq!(o.notification_writes,vec![{notification_expected}]);assert_eq!(o.linked_registrations,vec![true,false,false]);
 }}
 for bad_sp in [0u32,256,0x100001,0xfffffffcu32] {{assert!(run_raised(bad_sp,0x13579bdf,0,0,0xf0000,0x110000,0).is_err());}}
 assert!(run_raised(0x100000,0x13579bdf,0,0,0x110000,0xf0000,0).is_err());
 assert!(run_raised(0x100000,0x13579bdf,0,0,0x110000,0x120000,0).is_err());
 assert!(run_raised({module['end']}-4,0x13579bdf,0,0,{module['base']}-65536,{module['end']}+65536,0).is_err());
}}
'''
    (out/'native-raised.rs').write_text(source.read_text()+harness)
    native=out/('native-raised.exe' if os.name=='nt' else 'native-raised')
    command(['rustc','--edition=2021',out/'native-raised.rs','-o',native],'rustc',out,120)
    result=execute([str(native)],out/'native.stdout',out/'native.stderr',out/'native-launch',
        {'pe_sha256':info['pe_sha256']},{'exit':0,'feature_selector_cases':12,'trace_cases':3,'runtime_rejections':RUNTIME_REJECTIONS},timeout=10)
    if result.returncode or (out/'native.stdout').read_bytes() or (out/'native.stderr').read_bytes():
        raise ValueError('raised native assertions failed')
    negatives=compiled['rejections']
    info['evidence_stage']='original imported RaiseException invocation component compiled and executed; zero whole-PE translations'
    report=dict(info,kind='original raised-event instruction component, zero whole-PE translations',
        rust_sha256=sha(source.read_bytes()),harness_sha256=sha((out/'native-raised.rs').read_bytes()),
        harness_lf_sha256=sha((out/'native-raised.rs').read_bytes().replace(b'\r\n',b'\n')),
        native_sha256=sha(native.read_bytes()),native_platform=platform.platform(),native_os=os.name,
        deterministic_emission=True,case_provenance='15 inherited positive output scenarios; six retained runtime boundaries plus one aligned near-wrap case; five inherited compile mutations plus three new malformed invocation cases, no invented Windows observations',native_feature_selector_cases=12,native_trace_cases=3,native_runtime_rejections=RUNTIME_REJECTIONS,
        native_windows_component_cases=15 if os.name=='nt' else 0,
        native_linux_component_cases=15 if sys.platform.startswith('linux') else 0,
        original_windows_baseline_cases=1,whole_pe_translation_pairs=0,rejection_cases=negatives,
        original_report_sha256=sha((original/'report.json').read_bytes()),
        synthetic_inputs=dict(entry_sp=0x100000,cookie=0x13579bdf,thread_limit=0xf0000,thread_base=0x110000,
            context_selector_values=[stub,0],feature_values=[-2147483648,-1,0,1,2,2147483647],
            alternate_trace_entry_sp=0x200000,alternate_trace_cookie=0x2468ace0,
            caller_supplies_context_or_handler_stack=False),
        cross_host_rust_identical=None,
        notification_checks='12 ordered original writes in each of15 inherited positive cases; typed frame-index expectations do not claim equality to raw Windows addresses',
        comparison_limits=[
            'Numeric entry stack/cookie/thread bounds/feature and selector values are synthetic component inputs, not recorded Windows state; no supplied raw context or handler SP.',
            'Original Windows baseline observes EAX77 and stack/frame equality; absolute restored stack/frame values are checked independently against original instruction arithmetic only.',
            'Native component invokes the original RaiseException call under its bounded guest event contract and executes proved handler routing, local cleanup, helper bridges and application registrations; real OS context capture is not reconstructed. The closed RtlUnwind contract is not arbitrary Windows dispatch or whole-PE admission.',
            'GetModuleHandleW(NULL) returns the owned current image base in the declared single-module effect domain; module loading and ordinary CRT startup are not admitted.'])
    if windows is not None:report.update(verify_windows_component(windows,info,source.read_bytes(),(out/'native-raised.rs').read_bytes()))
    require_cross_host_result(report,require_windows_component)
    if require_windows_component and report.get('cross_host_harness_identical') is not True:
        raise ValueError('required cross-host harness verification did not complete')
    (out/'native-raised-report.json').write_text(json.dumps(report,indent=2)+'\n')
    return report



def selftest():
    import tempfile
    import unittest
    class GateTests(unittest.TestCase):
        def setUp(self):
            self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
            self.root=Path(self.tmp.name);self.windows=self.root/'raised-native-windows'
            self.windows.mkdir();(self.windows/'native-launch').mkdir()
            self.info=dict(pe_sha256='pe',source_sha256='source',object_sha256='object')
            (self.windows/'raised.rs').write_bytes(b'generated test source')
            (self.windows/'native-raised.rs').write_bytes(b'test harness')
            (self.windows/'native-launch/program.bin').write_bytes(b'test executable identity')
            self.report=dict(**self.info,rust_sha256=sha(b'generated test source'),
                harness_sha256=sha(b'test harness'),harness_lf_sha256=sha(b'test harness'),native_sha256=sha(b'test executable identity'),
                native_os='nt',whole_pe_translation_pairs=0,native_feature_selector_cases=12,
                native_trace_cases=3,native_runtime_rejections=RUNTIME_REJECTIONS,
                rejection_cases=[dict(case=n,exit=1,diagnostic='rejected') for n in REJECTION_NAMES])
            (self.windows/'native-launch/launch.json').write_text(json.dumps(dict(
                stage='finished',timeout=False,exit=0,stdout_hex='',stderr_hex='',executed_sha256=self.report['native_sha256'])))
            self.save()
        def save(self):
            (self.windows/'native-raised-report.json').write_text(json.dumps(self.report))
        def test_required_missing_and_self_reference_reject(self):
            with self.assertRaises(ValueError):windows_reference(self.root,self.windows,True)
            (self.windows/'native-raised-report.json').unlink()
            with self.assertRaises(ValueError):windows_reference(self.root,self.root/'linux',True)
            self.assertIsNone(windows_reference(self.root,self.root/'linux',False))
        def test_changed_files_original_identity_and_rust_reject(self):
            self.assertIsNone(verify_windows_component(self.windows,self.info))
            with self.assertRaises(ValueError):verify_windows_component(self.windows,dict(self.info,pe_sha256='other'))
            with self.assertRaises(ValueError):verify_windows_component(self.windows,self.info,b'different emitted source')
            with self.assertRaises(ValueError):verify_windows_component(self.windows,self.info,b'generated test source',b'changed expectations')
            (self.windows/'raised.rs').write_bytes(b'altered retained source')
            with self.assertRaises(ValueError):verify_windows_component(self.windows,self.info)
        def test_failed_launch_and_false_comparison_reject(self):
            result=verify_windows_component(self.windows,self.info,b'generated test source',b'test harness')
            require_cross_host_result(result,True)
            for incomplete in [{},{'cross_host_rust_identical':True},{'cross_host_rust_identical':True,'cross_host_same_original_pe':False}]:
                with self.assertRaises(ValueError):require_cross_host_result(incomplete,True)
            launch_path=self.windows/'native-launch/launch.json'
            launch=json.loads(launch_path.read_text());launch['timeout']=True;launch_path.write_text(json.dumps(launch))
            with self.assertRaises(ValueError):verify_windows_component(self.windows,self.info)
        def test_missing_conformance_rejection_cannot_claim_success(self):
            self.report['rejection_cases'].pop();self.save()
            with self.assertRaises(ValueError):verify_windows_component(self.windows,self.info)
    return unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(GateTests)).wasSuccessful()



if __name__=='__main__':
    if sys.argv[1:]==['--selftest']:raise SystemExit(0 if selftest() else 1)
    parser=argparse.ArgumentParser()
    parser.add_argument('original',type=Path);parser.add_argument('compiler',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--prepare-only',action='store_true')
    parser.add_argument('--require-windows-component',action='store_true')
    args=parser.parse_args()
    if args.prepare_only:
        if args.require_windows_component:parser.error('prepare-only cannot verify Windows component')
        args.output.mkdir(parents=True,exist_ok=False)
        info=prepare(args.original.resolve(),args.output.resolve())
        print(json.dumps(dict(stage=info['evidence_stage'],pe_sha256=info['pe_sha256'],whole_pe_translation_pairs=0)))
    else:
        report=check(args.original.resolve(),args.compiler.resolve(),args.output.resolve(),args.require_windows_component)
        print(json.dumps(dict(pe_sha256=report['pe_sha256'],rust_sha256=report['rust_sha256'],
            native_component_cases=15,runtime_rejections=RUNTIME_REJECTIONS,compile_rejections=len(report['rejection_cases']),
            cross_host_rust_identical=report['cross_host_rust_identical'],whole_pe_translation_pairs=0)))
