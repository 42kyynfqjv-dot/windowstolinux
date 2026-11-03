"""Connected original initializer/landing evidence, not whole-PE translation.

Windows observations are retained original-artifact values. Numeric stack,
cookie and current registers in native checks are independent synthetic inputs.
No saved CONTEXT array is supplied: original instructions construct it.
"""
import argparse
import json
import os
import platform
import shutil
import struct
import sys
from pathlib import Path

from check_frame import prepare as prepare_frames, command, sha, execute, require_cross_host_result
from frame_binding import frame_evidence
from inventory import mapped_bytes


REJECTION_NAMES = (
    'fill-length-crosses-guard','fill-destination-protected','wrong-module-iat',
    'wrong-fill-feature','truncated-fill-helper','landing-context-pointer',
    'landing-capture-register','truncated-landing-capture','prefix-record-argument',
    'prefix-unwind-branch','prefix-cookie-identity','wrong-context-selector','truncated-module-mapping',
)


def prepare(original,out):
    info=prepare_frames(original,out)
    evidence=frame_evidence(original)
    blocks={b['name']:b for b in evidence['fragments']}
    base=info['image_base'];pe=(original/'unwind.exe').read_bytes()
    pe_header=struct.unpack_from('<I',pe,60)[0]
    module_size=struct.unpack_from('<I',pe,pe_header+24+56)[0]
    if not module_size or base+module_size>0x100000000:raise ValueError('original image extent overflows address space')
    gap=blocks['main-unproved-gap'];activation=blocks['main-activate']
    start=gap['rva'];end=activation['rva']+activation['size']
    if start+gap['size']!=activation['rva']:
        raise ValueError('connected initializer omits original instructions')
    initializer=mapped_bytes(pe,base+start,end-start)
    (out/'connected-initializer.bin').write_bytes(initializer)
    lines=(out/'frame.manifest').read_text().splitlines()
    frame_rows=[i for i,l in enumerate(lines) if l.startswith('frame ')]
    if len(frame_rows)!=3:raise ValueError('original frame inventory changed')
    fields=lines[frame_rows[0]].split()
    fields[-2:]=['-','-'];lines[frame_rows[0]]=' '.join(fields)
    lines.append(f'connected-initializer {base+start} connected-initializer.bin')
    for kind,name in [('fill-helper','original-memset'),('selected-landing','selected-through-capture'),
                      ('handler-prefix','handler-through-installer'),('guard-helper','original-guard-validator'),
                      ('security-helper','original-security-check'),('context-helper','original-context-check')]:
        block=blocks[name]
        lines.append(f"{kind} {base+block['rva']} {block['file']}")
    features=evidence['connected']['memset_feature_words']
    if len(features)!=2:raise ValueError('original fill dispatch inventory changed')
    lines.append(f"context-selector {base+evidence['connected']['context_selector']['rva']}")
    lines.append('fill-features '+' '.join(str(base+w['rva']) for w in features))
    main=next(f for f in evidence['frames'] if f['symbol']=='_main')
    module=[c for c in main['blocked_calls'] if c.get('import')==['kernel32.dll','GetModuleHandleW']]
    if len(module)!=1:raise ValueError('original module result lacks exact imported API binding')
    lines.extend([f"module-iat {base+module[0]['target_rva']}",f'module-base {base}',f'module-size {module_size}'])
    (out/'frame.manifest').write_text('\n'.join(lines)+'\n')
    info['historical_fragment_boundaries']=info.pop('cuts')
    info['historical_main_gap']=info.pop('main_gap')
    info['historical_handler_prefix_obligations']=info['handler'].pop('unresolved')
    info['connected_proof_scope']=[
        'Original Main gap bytes are contiguous initializer input: zero-fill helper effects, GetModuleHandleW(NULL) ownership and scope activation are proved.',
        'Original handler prefix establishes normalizer/writeback/guard/context call order and pointer arguments; helpers are composed only in the valid guard, initialized same-thread context and zero exception-flags domain.',
        'Original selected landing constructs CONTEXT and invokes original Restore; captured EAX/ESP/EBP are instruction-derived, with no supplied saved-register array.',
        'Runtime boundary errors reject unsupported component inputs; they are not implementation of Windows fail-fast or arbitrary exception dispatch.']
    info['cuts']=[
        'Original Windows delivery/captured context and borrowed predecessor lifetime are explicit external inputs.',
        'Search and cleanup scheduling compose independently proved original instruction components; original handler full search/RtlUnwind bodies and FS teardown remain unexecuted.',
        'Ordinary CRT startup and whole-PE admission remain rejected.']
    info['module_mapping']=dict(base=base,size=module_size,end=base+module_size,provenance='PE32 OptionalHeader.SizeOfImage, includes image gaps and virtual tails')
    info['connected_initializer']=dict(rva=start,size=len(initializer),sha256=sha(initializer))
    info['connected_helpers']=evidence['connected']
    info['selected_through_capture']=blocks['selected-through-capture']
    (out/'connected-input-provenance.json').write_text(json.dumps(info,indent=2)+'\n')
    return info


def rejection_checks(compiler,out):
    def replace(directory,name,needle,new):
        p=directory/name;raw=p.read_bytes()
        if raw.count(needle)!=1:raise ValueError('mutation needs unique original binding: '+name)
        p.write_bytes(raw.replace(needle,new,1))
    def number(directory,kind,delta):
        path=directory/'frame.manifest';lines=path.read_text().splitlines()
        rows=[i for i,line in enumerate(lines) if line.startswith(kind+' ')]
        if len(rows)!=1:raise ValueError('mutation needs single manifest binding')
        i=rows[0];fields=lines[i].split();fields[1]=str(int(fields[1])+delta);lines[i]=' '.join(fields)
        path.write_text('\n'.join(lines)+'\n')
    def truncate(directory,name):
        path=directory/name;path.write_bytes(path.read_bytes()[:-1])
    def small_module(directory):
        path=directory/'frame.manifest'
        lines=path.read_text().splitlines()
        if sum(line.startswith('module-size ') for line in lines)!=1:raise ValueError('missing module extent')
        path.write_text('\n'.join('module-size 4096' if line.startswith('module-size ') else line for line in lines)+'\n')
    mutations=[
        ('fill-length-crosses-guard',lambda d:replace(d,'connected-initializer.bin',bytes.fromhex('68cc020000'),bytes.fromhex('68d0020000'))),
        ('fill-destination-protected',lambda d:replace(d,'connected-initializer.bin',bytes.fromhex('8d8518fdffff'),bytes.fromhex('8d85e4ffffff'))),
        ('wrong-module-iat',lambda d:number(d,'module-iat',4)),
        ('wrong-fill-feature',lambda d:number(d,'fill-features',4)),
        ('truncated-fill-helper',lambda d:truncate(d,'original-memset.bin')),
        ('landing-context-pointer',lambda d:replace(d,'selected-through-capture.bin',bytes.fromhex('8d8d18fdffff'),bytes.fromhex('8d8de4ffffff'))),
        ('landing-capture-register',lambda d:replace(d,'selected-through-capture.bin',bytes.fromhex('89850cfdffff'),bytes.fromhex('898d0cfdffff'))),
        ('truncated-landing-capture',lambda d:truncate(d,'selected-through-capture.bin')),
        ('prefix-record-argument',lambda d:replace(d,'handler-through-installer.bin',bytes.fromhex('8b5d08'),bytes.fromhex('8b5d10'))),
        ('prefix-unwind-branch',lambda d:replace(d,'handler-through-installer.bin',bytes.fromhex('755a'),bytes.fromhex('745a'))),
        ('prefix-cookie-identity',lambda d:number(d,'cookie',4)),
        ('wrong-context-selector',lambda d:number(d,'context-selector',4)),
        ('truncated-module-mapping',small_module),
    ]
    if tuple(name for name,_ in mutations)!=REJECTION_NAMES:raise ValueError('connected rejection inventory mismatch')
    results=[]
    for name,mutate in mutations:
        directory=out/'negative'/name;directory.mkdir(parents=True)
        for path in out.iterdir():
            if path.is_file() and (path.suffix=='.bin' or path.name=='frame.manifest'):
                shutil.copyfile(path,directory/path.name)
        mutate(directory)
        result=command([compiler,directory,directory/'rejected.rs'],name,directory,120,False)
        diagnostic=result.stderr.decode(errors='replace')
        if result.returncode==0 or not diagnostic.strip() or 'panicked' in diagnostic:
            raise ValueError('connected mutation did not reject safely: '+name)
        results.append(dict(case=name,exit=result.returncode,diagnostic=diagnostic.strip()))
    return results


def windows_reference(original,out,required):
    directory=original/'connected-native-windows'
    if directory.resolve()==out.resolve():
        if required:raise ValueError('Windows evidence cannot be the current output')
        return None
    if not (directory/'native-connected-report.json').is_file():
        if required:raise ValueError('required retained Windows connected component is missing')
        return None
    return directory


def verify_windows_component(directory,info,local_rust=None,local_harness=None):
    prior=json.loads((directory/'native-connected-report.json').read_text())
    for key in ['pe_sha256','source_sha256','object_sha256']:
        if prior.get(key)!=info[key]:raise ValueError('Windows connected original identity mismatch: '+key)
    source=(directory/'connected.rs').read_bytes()
    harness=(directory/'native-connected.rs').read_bytes()
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
        raise ValueError('Windows connected files/launch provenance failed')
    if (prior.get('native_feature_selector_cases')!=12 or prior.get('native_trace_cases')!=3
            or prior.get('native_runtime_rejections')!=10
            or tuple(r.get('case') for r in prior.get('rejection_cases',[]))!=REJECTION_NAMES
            or any(type(r.get('exit')) is not int or r['exit']==0 or not r.get('diagnostic')
                   or 'panicked' in r['diagnostic'] for r in prior.get('rejection_cases',[]))):
        raise ValueError('Windows connected conformance inventory differs')
    if local_rust is None:return None
    if source!=local_rust:raise ValueError('Windows/Linux connected Rust differs')
    if local_harness is None or harness_lf!=local_harness.replace(b'\r\n',b'\n'):
        raise ValueError('Windows/Linux connected harness or input expectations differ')
    return dict(cross_host_rust_identical=True,cross_host_same_original_pe=True,cross_host_harness_identical=True,
        native_windows_component_cases=15,
        native_windows_report_sha256=sha((directory/'native-connected-report.json').read_bytes()))


def check(original,compiler,out,require_windows_component=False):
    windows=windows_reference(original,out,require_windows_component)
    out.mkdir(parents=True,exist_ok=False)
    info=prepare(original,out)
    if windows is not None:verify_windows_component(windows,info)
    source=out/'connected.rs';repeat=out/'connected-repeat.rs'
    command([compiler,out,source],'conversion',out,120)
    command([compiler,out,repeat],'repeat-conversion',out,120)
    if source.read_bytes()!=repeat.read_bytes():raise ValueError('connected source is not deterministic')
    expected=info['windows_observed']
    globals_expected=','.join(f"Some({g['expected']}u32)" for g in info['globals'])
    target=info['restore_target_va']
    stub=info['image_base']+info['connected_helpers']['context_selector']['comparison_stub_rva']
    inner_local,inner_cursor=info['owner_offsets']['_Inner']
    outer_local,outer_cursor=info['owner_offsets']['_Outer']
    module=info['module_mapping']
    harness=f'''
fn main() {{
 let current=[1u32,2,3,40,0x100000-4096,8192,60,70,123,514];
 // Independent original instruction arithmetic: push EBP (4), four record
 // words (16), ADD ESP,-764, four saved words (16): frame SP=entry-800.
 for feature in [i32::MIN,-1,0,1,2,i32::MAX] {{
  for selector in [{stub}u32,0u32] {{
   let entry_sp=0x100000u32;
   let o=run_connected(entry_sp,0x13579bdf,current,feature,0,0xf0000,0x110000,selector,entry_sp-8192).unwrap();
   assert_eq!(o.trace,{expected['trace']});assert_eq!(o.globals,vec![{globals_expected}]);
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
  let o=run_connected(0x200000,0x2468ace0,moved,0,initial,0x1f0000,0x210000,0,0x200000-8192).unwrap();assert_eq!(o.trace,expected_trace);
  assert_eq!(o.restored[4],Some(0x200000-800));assert_eq!(o.restored[5],Some(0x200000-4));
 }}
 for bad_sp in [0u32,256,0x100001] {{assert!(run_connected(bad_sp,0x13579bdf,current,0,0,0xf0000,0x110000,0,0x100000-8192).is_err());}}
 let mut bad=current;bad[9]|=0x100;assert!(run_connected(0x100000,0x13579bdf,bad,0,0,0xf0000,0x110000,0,0x100000-8192).is_err());
 assert!(run_connected(0x100000,0x13579bdf,current,0,0,0x110000,0xf0000,0,0x100000-8192).is_err());
 assert!(run_connected(0x100000,0x13579bdf,current,0,0,0x110000,0x120000,0,0x100000-8192).is_err());
 let mut module_current=current;module_current[4]={module['base']}-4096;
 assert!(run_connected({module['end']}-4,0x13579bdf,module_current,0,0,{module['base']}-65536,{module['end']}+65536,0,{module['base']}-8192).is_err());
 for handler_sp in [0x100000-64,0xf0000+72,0xefff0] {{assert!(run_connected(0x100000,0x13579bdf,current,0,0,0xf0000,0x110000,0,handler_sp).is_err());}}
}}
'''
    (out/'native-connected.rs').write_text(source.read_text()+harness)
    native=out/('native-connected.exe' if os.name=='nt' else 'native-connected')
    command(['rustc','--edition=2021',out/'native-connected.rs','-o',native],'rustc',out,120)
    result=execute([str(native)],out/'native.stdout',out/'native.stderr',out/'native-launch',
        {'pe_sha256':info['pe_sha256']},{'exit':0,'feature_selector_cases':12,'trace_cases':3,'runtime_rejections':10},timeout=10)
    if result.returncode or (out/'native.stdout').read_bytes() or (out/'native.stderr').read_bytes():
        raise ValueError('connected native assertions failed')
    negatives=rejection_checks(compiler,out)
    report=dict(kind='original connected instruction component, zero whole-PE translations',**info,
        rust_sha256=sha(source.read_bytes()),harness_sha256=sha((out/'native-connected.rs').read_bytes()),
        harness_lf_sha256=sha((out/'native-connected.rs').read_bytes().replace(b'\r\n',b'\n')),
        native_sha256=sha(native.read_bytes()),native_platform=platform.platform(),native_os=os.name,
        deterministic_emission=True,native_feature_selector_cases=12,native_trace_cases=3,native_runtime_rejections=10,
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
        comparison_limits=[
            'Numeric initial stack/cookie/current registers/thread bounds/feature and selector values are synthetic native inputs, not recorded Windows thread state.',
            'Original Windows baseline observes EAX77 and stack/frame equality; absolute restored stack/frame values are checked independently against original instruction arithmetic only.',
            'Native execution follows proven original initializer, handler-prefix helper effects, cleanup, selected landing and restore component; Windows dispatch/search/RtlUnwind and FS teardown remain outside this composition.',
            'GetModuleHandleW(NULL) returns the owned current image base in the declared single-module effect domain; module loading and ordinary CRT startup are not admitted.'])
    if windows is not None:report.update(verify_windows_component(windows,info,source.read_bytes(),(out/'native-connected.rs').read_bytes()))
    require_cross_host_result(report,require_windows_component)
    if require_windows_component and report.get('cross_host_harness_identical') is not True:
        raise ValueError('required cross-host harness verification did not complete')
    (out/'native-connected-report.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def selftest():
    import tempfile
    import unittest
    class GateTests(unittest.TestCase):
        def setUp(self):
            self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
            self.root=Path(self.tmp.name);self.windows=self.root/'connected-native-windows'
            self.windows.mkdir();(self.windows/'native-launch').mkdir()
            self.info=dict(pe_sha256='pe',source_sha256='source',object_sha256='object')
            (self.windows/'connected.rs').write_bytes(b'generated test source')
            (self.windows/'native-connected.rs').write_bytes(b'test harness')
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
            (self.windows/'native-connected-report.json').write_text(json.dumps(self.report))
        def test_required_missing_and_self_reference_reject(self):
            with self.assertRaises(ValueError):windows_reference(self.root,self.windows,True)
            (self.windows/'native-connected-report.json').unlink()
            with self.assertRaises(ValueError):windows_reference(self.root,self.root/'linux',True)
            self.assertIsNone(windows_reference(self.root,self.root/'linux',False))
        def test_changed_files_original_identity_and_rust_reject(self):
            self.assertIsNone(verify_windows_component(self.windows,self.info))
            with self.assertRaises(ValueError):verify_windows_component(self.windows,dict(self.info,pe_sha256='other'))
            with self.assertRaises(ValueError):verify_windows_component(self.windows,self.info,b'different emitted source')
            with self.assertRaises(ValueError):verify_windows_component(self.windows,self.info,b'generated test source',b'changed expectations')
            (self.windows/'connected.rs').write_bytes(b'altered retained source')
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
    if sys.argv[1:]==['--selftest']:
        raise SystemExit(0 if selftest() else 1)
    parser=argparse.ArgumentParser()
    parser.add_argument('original',type=Path);parser.add_argument('compiler',type=Path)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--prepare-only',action='store_true')
    parser.add_argument('--require-windows-component',action='store_true')
    args=parser.parse_args()
    if args.prepare_only:
        if args.require_windows_component:parser.error('prepare-only cannot verify Windows component')
        args.output.mkdir(parents=True,exist_ok=False)
        info=prepare(args.original.resolve(),args.output.resolve())
        print(json.dumps(dict(stage='prepared only',pe_sha256=info['pe_sha256'])))
    else:
        report=check(args.original.resolve(),args.compiler.resolve(),args.output.resolve(),args.require_windows_component)
        print(json.dumps({k:report[k] for k in ['kind','pe_sha256','rust_sha256','native_feature_selector_cases','native_trace_cases','native_runtime_rejections','whole_pe_translation_pairs']}))
