"""Original dispatcher/FS composition evidence preparation.

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

REGIONS=(
    ('handler-complete','original-handler-complete'),
    ('local-unwind','original-local-unwind'),
    ('nested-handler','original-nested-handler'),
    ('filter-bridge','original-filter-bridge'),
    ('selected-transfer','original-selected-transfer'),
    ('global-unwind-wrapper','original-global-unwind-wrapper'),
    ('local-unwind-wrapper','original-local-unwind-wrapper'),
    ('notification','original-notification'),
    ('cleanup-bridge','original-cleanup-bridge'),
)
REJECTION_NAMES=('wrong-complete-handler-identity','wrong-rtl-unwind-iat',
    'aliased-notification-words','temporary-fs-head-offset','scope-parent-cycle')


def prepare(original,out):
    info=prepare_connected(original,out)
    evidence=frame_evidence(original)
    blocks={b['name']:b for b in evidence['fragments']}
    dispatch=evidence['dispatch'];base=info['image_base']
    pe=(original/'unwind.exe').read_bytes()
    lines=(out/'frame.manifest').read_text().splitlines()
    # Legacy connected range binding lists the adapter bridge as a filter. The
    # full dispatcher now owns that exact region separately; it is not a C
    # language filter and cannot appear twice as two executable capabilities.
    bridge=blocks['original-filter-bridge']
    bridge_row=f"filter {base+bridge['rva']} {bridge['file']}"
    if lines.count(bridge_row)!=1 or (out/bridge['file']).read_bytes()!=mapped_bytes(pe,base+bridge['rva'],bridge['size']):
        raise ValueError('legacy filter-bridge row lacks exact original identity')
    lines.remove(bridge_row)
    bound=[]
    for kind,name in REGIONS:
        block=blocks[name];raw=(out/block['file']).read_bytes()
        if raw!=mapped_bytes(pe,base+block['rva'],block['size']):
            raise ValueError('dispatcher region differs from unchanged original PE: '+name)
        lines.append(f"{kind} {base+block['rva']} {block['file']}")
        bound.append(dict(kind=kind,rva=block['rva'],size=len(raw),sha256=sha(raw),file=block['file']))
    lines.append(f"rtl-unwind-iat {base+dispatch['rtl_unwind_iat_rva']}")
    # The instruction-derived three stores bind addresses, never initial values.
    # The signature/other bytes are not read or asserted by this composition.
    nlg=base+dispatch['notification_record_rva']
    lines.append(f'notification-words {nlg+8} {nlg+4} {nlg+12}')
    (out/'frame.manifest').write_text('\n'.join(lines)+'\n')
    info['historical_connected_boundaries']=info.pop('cuts')
    info['dispatch_regions']=bound
    info['dispatch_metadata']=dispatch
    info['notification_binding']=dict(action=nlg+8,target=nlg+4,frame=nlg+12,
        initial_values='unknown until instruction-derived stores; signature not asserted')
    frames={frame['symbol']:frame for frame in evidence['frames']}
    # Independent frozen-source order: Inner's inner finally A, then its outer
    # finally B, then Outer's finally C, then Main's selected handler. Bind code
    # addresses from the unchanged original EH4 rows, never generated output.
    events=[]
    for symbol,row_index,owner,reason in [('_Inner',1,2,0x101),('_Inner',0,2,0x101),
                                       ('_Outer',0,1,0x101),('_main',0,0,1)]:
        row=frames[symbol]['table']['rows'][row_index]
        events.extend([(nlg+8,0,reason),(nlg+4,1,base+row['handler_rva']),(nlg+12,2,owner)])
    info['expected_notification_writes']=events
    info['notification_expectation_provenance']='Frozen source lexical cleanup/selection order plus original EH4 target RVAs; independently corroborated by separately instrumented Windows run, not derived from emitter'
    info['notification_value_kinds']={'0':'scalar','1':'preferred-image original code VA','2':'owned frame index; NOT observed raw Windows frame pointer'}

    info['cuts']=[
        'Incoming Windows delivery, initial captured context and borrowed predecessor lifetime remain external inputs.',
        'RtlUnwind is admitted only under the explicitly reviewed closed application-registration domain; observation of one Windows run is not a general API proof.',
        'Unproved callbacks, secondary/collided exceptions and arbitrary Windows startup remain rejected.',
        'Original dispatcher/native composition is a component; ordinary CRT and whole-PE conversion remain rejected.']
    info['evidence_stage']='prepared original-byte bindings only; no new native execution claim'
    info['whole_pe_translation_pairs']=0
    (out/'dispatched-input-provenance.json').write_text(json.dumps(info,indent=2)+'\n')
    return info


def mutation_directories(out):
    def rewrite(directory,kind,index,value):
        path=directory/'frame.manifest';lines=path.read_text().splitlines()
        rows=[i for i,line in enumerate(lines) if line.startswith(kind+' ')]
        if len(rows)!=1:raise ValueError('mutation manifest singleton missing: '+kind)
        fields=lines[rows[0]].split();fields[index]=str(value(fields))
        lines[rows[0]]=' '.join(fields);path.write_text('\n'.join(lines)+'\n')
    def temporary_offset(directory):
        path=directory/'original-local-unwind.bin';raw=path.read_bytes()
        # Original saved previous FS head is popped into FS:[0]. Writing
        # FS:[4] instead corrupts the thread stack-base field, not its head.
        old=bytes.fromhex('648f0500000000')
        if raw.count(old)!=1:raise ValueError('temporary FS restoration binding is not unique')
        # POP FS:[4] must not be treated as the original FS:[0] restore.
        path.write_bytes(raw.replace(old,bytes.fromhex('648f0504000000'),1))
    def parent_cycle(directory):
        rows=[line.split() for line in (directory/'frame.manifest').read_text().splitlines() if line.startswith('frame ')]
        if len(rows)!=3:raise ValueError('scope mutation requires bound original frames')
        table=directory/rows[0][4];raw=bytearray(table.read_bytes())
        if len(raw)<28:raise ValueError('scope mutation lacks complete row')
        struct.pack_into('<i',raw,16,0);table.write_bytes(raw)
    mutations=[
        (REJECTION_NAMES[0],lambda d:rewrite(d,'handler-complete',1,lambda f:int(f[1])+1)),
        (REJECTION_NAMES[1],lambda d:rewrite(d,'rtl-unwind-iat',1,lambda f:int(f[1])+4)),
        (REJECTION_NAMES[2],lambda d:rewrite(d,'notification-words',2,lambda f:f[1])),
        (REJECTION_NAMES[3],temporary_offset),
        (REJECTION_NAMES[4],parent_cycle),
    ]
    result=[]
    for name,mutate in mutations:
        directory=out/'negative'/name;directory.mkdir(parents=True,exist_ok=False)
        for path in out.iterdir():
            if path.is_file() and (path.suffix=='.bin' or path.name=='frame.manifest'):
                shutil.copyfile(path,directory/path.name)
        mutate(directory);result.append((name,directory))
    return result


def check_compile(compiler,out):
    source=out/'dispatched.rs';repeat=out/'dispatched-repeat.rs'
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
    (out/'dispatched-compile-report.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def windows_reference(original,out,required):
    directory=original/'dispatched-native-windows'
    if directory.resolve()==out.resolve():
        if required:raise ValueError('Windows evidence cannot be the current output')
        return None
    if not (directory/'native-dispatched-report.json').is_file():
        if required:raise ValueError('required retained Windows dispatched component is missing')
        return None
    return directory


def verify_windows_component(directory,info,local_rust=None,local_harness=None):
    prior=json.loads((directory/'native-dispatched-report.json').read_text())
    for key in ['pe_sha256','source_sha256','object_sha256']:
        if prior.get(key)!=info[key]:raise ValueError('Windows dispatched original identity mismatch: '+key)
    source=(directory/'dispatched.rs').read_bytes()
    harness=(directory/'native-dispatched.rs').read_bytes()
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
        raise ValueError('Windows dispatched files/launch provenance failed')
    if (prior.get('native_feature_selector_cases')!=12 or prior.get('native_trace_cases')!=3
            or prior.get('native_runtime_rejections')!=10
            or tuple(r.get('case') for r in prior.get('rejection_cases',[]))!=REJECTION_NAMES
            or any(type(r.get('exit')) is not int or r['exit']==0 or not r.get('diagnostic')
                   or 'panicked' in r['diagnostic'] for r in prior.get('rejection_cases',[]))):
        raise ValueError('Windows dispatched conformance inventory differs')
    if local_rust is None:return None
    if source!=local_rust:raise ValueError('Windows/Linux dispatched Rust differs')
    if local_harness is None or harness_lf!=local_harness.replace(b'\r\n',b'\n'):
        raise ValueError('Windows/Linux dispatched harness or input expectations differ')
    return dict(cross_host_rust_identical=True,cross_host_same_original_pe=True,cross_host_harness_identical=True,
        native_windows_component_cases=15,
        native_windows_report_sha256=sha((directory/'native-dispatched-report.json').read_bytes()))



def check(original,compiler,out,require_windows_component=False):
    windows=windows_reference(original,out,require_windows_component)
    out.mkdir(parents=True,exist_ok=False)
    info=prepare(original,out)
    if windows is not None:verify_windows_component(windows,info)
    compiled=check_compile(compiler,out)
    source=out/'dispatched.rs'
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
 let current=[1u32,2,3,40,0x100000-4096,8192,60,70,123,514];
 // Independent original instruction arithmetic: push EBP (4), four record
 // words (16), ADD ESP,-764, four saved words (16): frame SP=entry-800.
 for feature in [i32::MIN,-1,0,1,2,i32::MAX] {{
  for selector in [{stub}u32,0u32] {{
   let entry_sp=0x100000u32;
   let o=run_dispatched(entry_sp,0x13579bdf,current,feature,0,0xf0000,0x110000,selector,entry_sp-8192).unwrap();
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
   assert_eq!(o.restored[0],Some(77));assert_eq!(o.restored[4],Some(entry_sp-800));assert_eq!(o.restored[5],Some(entry_sp-4));assert_eq!(o.restored[8],Some({target}));
  }}
 }}
 for (initial,expected_trace) in [(1u32,4387u32),(1048576,291),(u32::MAX,4294963491)] {{
  let mut moved=current;moved[4]=0x200000-4096;
  let o=run_dispatched(0x200000,0x2468ace0,moved,0,initial,0x1f0000,0x210000,0,0x200000-8192).unwrap();assert_eq!(o.trace,expected_trace);
  assert_eq!(o.restored[4],Some(0x200000-800));assert_eq!(o.restored[5],Some(0x200000-4));
  assert_eq!(o.notification_writes,vec![{notification_expected}]);assert_eq!(o.linked_registrations,vec![true,false,false]);
 }}
 for bad_sp in [0u32,256,0x100001] {{assert!(run_dispatched(bad_sp,0x13579bdf,current,0,0,0xf0000,0x110000,0,0x100000-8192).is_err());}}
 let mut bad=current;bad[9]|=0x100;assert!(run_dispatched(0x100000,0x13579bdf,bad,0,0,0xf0000,0x110000,0,0x100000-8192).is_err());
 assert!(run_dispatched(0x100000,0x13579bdf,current,0,0,0x110000,0xf0000,0,0x100000-8192).is_err());
 assert!(run_dispatched(0x100000,0x13579bdf,current,0,0,0x110000,0x120000,0,0x100000-8192).is_err());
 let mut module_current=current;module_current[4]={module['base']}-4096;
 assert!(run_dispatched({module['end']}-4,0x13579bdf,module_current,0,0,{module['base']}-65536,{module['end']}+65536,0,{module['base']}-8192).is_err());
 for handler_sp in [0x100000-64,0xf0000+72,0xefff0] {{assert!(run_dispatched(0x100000,0x13579bdf,current,0,0,0xf0000,0x110000,0,handler_sp).is_err());}}
}}
'''
    (out/'native-dispatched.rs').write_text(source.read_text()+harness)
    native=out/('native-dispatched.exe' if os.name=='nt' else 'native-dispatched')
    command(['rustc','--edition=2021',out/'native-dispatched.rs','-o',native],'rustc',out,120)
    result=execute([str(native)],out/'native.stdout',out/'native.stderr',out/'native-launch',
        {'pe_sha256':info['pe_sha256']},{'exit':0,'feature_selector_cases':12,'trace_cases':3,'runtime_rejections':10},timeout=10)
    if result.returncode or (out/'native.stdout').read_bytes() or (out/'native.stderr').read_bytes():
        raise ValueError('dispatched native assertions failed')
    negatives=compiled['rejections']
    info['evidence_stage']='original dispatcher component compiled and executed; zero whole-PE translations'
    report=dict(info,kind='original dispatcher/FS instruction component, zero whole-PE translations',
        rust_sha256=sha(source.read_bytes()),harness_sha256=sha((out/'native-dispatched.rs').read_bytes()),
        harness_lf_sha256=sha((out/'native-dispatched.rs').read_bytes().replace(b'\r\n',b'\n')),
        native_sha256=sha(native.read_bytes()),native_platform=platform.platform(),native_os=os.name,
        deterministic_emission=True,case_provenance='15 positive and 10 runtime-negative input cases inherited from connected component; exercised through new original dispatcher composition, not 25 newly invented cases',native_feature_selector_cases=12,native_trace_cases=3,native_runtime_rejections=10,
        native_windows_component_cases=15 if os.name=='nt' else 0,
        native_linux_component_cases=15 if sys.platform.startswith('linux') else 0,
        original_windows_baseline_cases=1,whole_pe_translation_pairs=0,rejection_cases=negatives,
        original_report_sha256=sha((original/'report.json').read_bytes()),
        synthetic_inputs=dict(entry_sp=0x100000,cookie=0x13579bdf,captured_esp=0x100000-4096,
            handler_sp=0x100000-8192,thread_limit=0xf0000,thread_base=0x110000,
            context_selector_values=[stub,0],feature_values=[-2147483648,-1,0,1,2,2147483647],
            alternate_trace_entry_sp=0x200000,alternate_trace_cookie=0x2468ace0,
            captured_context_is_original_windows_observation=False),
        cross_host_rust_identical=None,
        notification_checks='12 ordered original writes in each of15 inherited positive cases; typed frame-index expectations do not claim equality to raw Windows addresses',
        comparison_limits=[
            'Numeric initial stack/cookie/current registers/thread bounds/feature and selector values are synthetic native inputs, not recorded Windows thread state.',
            'Original Windows baseline observes EAX77 and stack/frame equality; absolute restored stack/frame values are checked independently against original instruction arithmetic only.',
            'Native component executes proved original handler routing, local cleanup, helper bridges and application registration effects; incoming Windows delivery and the explicitly bounded RtlUnwind contract remain external boundaries. This is not whole-PE translation or arbitrary OS dispatch.',
            'GetModuleHandleW(NULL) returns the owned current image base in the declared single-module effect domain; module loading and ordinary CRT startup are not admitted.'])
    if windows is not None:report.update(verify_windows_component(windows,info,source.read_bytes(),(out/'native-dispatched.rs').read_bytes()))
    require_cross_host_result(report,require_windows_component)
    if require_windows_component and report.get('cross_host_harness_identical') is not True:
        raise ValueError('required cross-host harness verification did not complete')
    (out/'native-dispatched-report.json').write_text(json.dumps(report,indent=2)+'\n')
    return report



def selftest():
    import tempfile
    import unittest
    class GateTests(unittest.TestCase):
        def setUp(self):
            self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
            self.root=Path(self.tmp.name);self.windows=self.root/'dispatched-native-windows'
            self.windows.mkdir();(self.windows/'native-launch').mkdir()
            self.info=dict(pe_sha256='pe',source_sha256='source',object_sha256='object')
            (self.windows/'dispatched.rs').write_bytes(b'generated test source')
            (self.windows/'native-dispatched.rs').write_bytes(b'test harness')
            (self.windows/'native-launch/program.bin').write_bytes(b'test executable identity')
            self.report=dict(**self.info,rust_sha256=sha(b'generated test source'),
                harness_sha256=sha(b'test harness'),harness_lf_sha256=sha(b'test harness'),native_sha256=sha(b'test executable identity'),
                native_os='nt',whole_pe_translation_pairs=0,native_feature_selector_cases=12,
                native_trace_cases=3,native_runtime_rejections=10,
                rejection_cases=[dict(case=n,exit=1,diagnostic='rejected') for n in REJECTION_NAMES])
            (self.windows/'native-launch/launch.json').write_text(json.dumps(dict(
                stage='finished',timeout=False,exit=0,stdout_hex='',stderr_hex='',executed_sha256=self.report['native_sha256'])))
            self.save()
        def save(self):
            (self.windows/'native-dispatched-report.json').write_text(json.dumps(self.report))
        def test_required_missing_and_self_reference_reject(self):
            with self.assertRaises(ValueError):windows_reference(self.root,self.windows,True)
            (self.windows/'native-dispatched-report.json').unlink()
            with self.assertRaises(ValueError):windows_reference(self.root,self.root/'linux',True)
            self.assertIsNone(windows_reference(self.root,self.root/'linux',False))
        def test_changed_files_original_identity_and_rust_reject(self):
            self.assertIsNone(verify_windows_component(self.windows,self.info))
            with self.assertRaises(ValueError):verify_windows_component(self.windows,dict(self.info,pe_sha256='other'))
            with self.assertRaises(ValueError):verify_windows_component(self.windows,self.info,b'different emitted source')
            with self.assertRaises(ValueError):verify_windows_component(self.windows,self.info,b'generated test source',b'changed expectations')
            (self.windows/'dispatched.rs').write_bytes(b'altered retained source')
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
            native_component_cases=15,runtime_rejections=10,compile_rejections=len(report['rejection_cases']),
            cross_host_rust_identical=report['cross_host_rust_identical'],whole_pe_translation_pairs=0)))
