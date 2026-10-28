"""Conditional original-Main report completion; never whole-PE/CRT admission.

Expected scalar values come from the frozen authored source and original symbol
RVAs. Retained Windows stdout separately checks physical text-mode bytes. Sink
failure controls model explicit component policies, not unobserved CRT behavior.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import struct
import tempfile
import unittest

from check_raised import prepare as prepare_raised,mutation_directories as raised_mutations
from check_raised import REJECTION_NAMES as RAISED_REJECTIONS
from check_frame import command,sha,execute,require_cross_host_result
from reported_binding import extract

REJECTION_NAMES=RAISED_REJECTIONS+('report-pointer-format','printf-wrong-cleanup','iob-owned-code-alias',
    'completion-wrong-guard-owner','missing-report-entry-global')


def independent_arguments(info,trace=291,abandoned=0):
    observed=info['report_symbol_rvas']
    # RVAs independently rebound from the original artifact; scalar semantics
    # frozen in source: ((0*16+1)*16+2)*16+3,100+7+11,200+13.
    return [observed['table_rva'],*observed['cleanup_rvas'],observed['restore_rva'],observed['restore_target_rva'],
            trace,100+7+11,200+13,300,1,abandoned,-1,-1,77,1,1]


def expected_output(arguments):
    if len(arguments)!=17:raise ValueError('independent report vector needs17 values')
    # Independent field order from frozen source, not generated native output.
    values=dict(table_rva=arguments[0],cleanup_rvas=arguments[1:4],restore_rva=arguments[4],
        restore_target_rva=arguments[5],trace=arguments[6],inner=arguments[7],outer=arguments[8],
        selected=arguments[9],handled=arguments[10],abandoned=arguments[11],inner_cursor=arguments[12],
        outer_cursor=arguments[13],restore_eax=arguments[14],restore_stack_equal=arguments[15],restore_frame_equal=arguments[16])
    logical=json.dumps(values,separators=(',',':')).encode('ascii')+b'\n'
    return logical,logical.replace(b'\n',b'\r\n')


def prepare(original,out):
    info=prepare_raised(original,out);binding=extract(original,out)
    manifest=out/'frame.manifest';lines=manifest.read_text().splitlines()
    lines.append('reported-component')
    for region in binding['regions']:lines.append(f"{region['name']} {region['va']} {region['file']}")
    lines.append(f"formatter {binding['formatter_va']}")
    owned={g['va'] for g in info['globals']}
    owned.add(next(int(line.split()[1]) for line in lines if line.startswith('trace ')))
    extra=[info['image_base']+word['rva'] for word in binding['scalar_reads'] if info['image_base']+word['rva'] not in owned]
    if len(extra)!=1:raise ValueError('frozen source extra completion-state inventory changed')
    lines.extend(f'reported-global {va}' for va in extra)
    manifest.write_text('\n'.join(lines)+'\n')
    # Bind source-derived RVA expectations to independently extracted code/data.
    def rva(kind):
        matches=[line.split() for line in lines if line.startswith(kind+' ')]
        if len(matches)!=1:raise ValueError('reported original symbol binding missing: '+kind)
        return int(matches[0][1])-info['image_base']
    cleanup_rows=[line.split() for line in lines if line.startswith('cleanup ')]
    if [row[2] for row in cleanup_rows]!=['CleanupA.bin','CleanupB.bin','CleanupC.bin']:
        raise ValueError('reported frozen cleanup symbol order changed')
    info['report_symbol_rvas']=dict(table_rva=rva('dispatch-table'),cleanup_rvas=[int(row[1])-info['image_base'] for row in cleanup_rows],
        restore_rva=rva('restore'),restore_target_rva=rva('target'))
    arguments=independent_arguments(info);logical,physical=expected_output(arguments)
    launch=json.loads((original/'launch/launch.json').read_text())
    if bytes.fromhex(launch['stdout_hex'])!=physical or launch['stderr_hex']!='' or launch['exit']!=0:
        raise ValueError('independent source report differs from actual original Windows bytes/exit')
    info['report_binding']=binding
    info['reported_entry_globals']=extra
    info['independent_report_arguments']=arguments
    info['expected_logical_hex']=logical.hex();info['expected_physical_hex']=physical.hex()
    info['report_contract_limits']=[
        'Original printf wrapper and scalar argument instructions are bound; linked formatter body, CRT stream initialization, options lifetime and actual exit/flush composition remain external contracts.',
        'Deferred policy produces pending bytes; only an explicit successful flush yields the compared physical CRLF bytes.',
        'Main return is instruction-derived and distinct from whole-process exit. Sink failure tests do not establish original CRT error/invalid-parameter behavior.',
        '17values plus format pointer consume18stack words. Windows long is32bits; logical character count and physical CRLF bytes differ.',
        'Extra completion scalar is an explicit runtime argument; file zero-fill is not an assumed runtime value.',
        'Accessor arithmetic binds a caller-owned stdout address; accepting a different proven stride does not certify the linked CRT FILE layout.']
    info['whole_pe_translation_pairs']=0
    (out/'reported-input-provenance.json').write_text(json.dumps(info,indent=2)+'\n')
    return info


def mutation_directories(out):
    result=raised_mutations(out)
    def replace(directory,name,old,new):
        path=directory/name;raw=path.read_bytes()
        if raw.count(old)!=1:raise ValueError('reported mutation requires unique instruction')
        path.write_bytes(raw.replace(old,new,1))
    def bad_format(directory):
        path=directory/'printf-format.bin';raw=path.read_bytes()
        if b'%lu' not in raw:raise ValueError('missing original unsigned format')
        path.write_bytes(raw.replace(b'%lu',b'%ls',1))
    def missing_global(directory):
        path=directory/'frame.manifest';lines=path.read_text().splitlines()
        if sum(line.startswith('reported-global ') for line in lines)!=1:raise ValueError('entry-global mutation inventory')
        path.write_text('\n'.join(line for line in lines if not line.startswith('reported-global '))+'\n')
    def code_alias(directory):
        rows=[line.split() for line in (directory/'frame.manifest').read_text().splitlines() if line.startswith('printf-wrapper ')]
        if len(rows)!=1:raise ValueError('missing unique wrapper for alias mutation')
        path=directory/'iob-helper.bin';raw=bytearray(path.read_bytes())
        if len(raw)!=16 or raw[5:9]!=bytes.fromhex('6b450838') or raw[9]!=5:raise ValueError('original accessor binding changed')
        raw[10:14]=struct.pack('<I',int(rows[0][1])-56);path.write_bytes(raw)
    cases=[('report-pointer-format',bad_format),
        ('printf-wrong-cleanup',lambda d:replace(d,'printf-wrapper.bin',bytes.fromhex('83c418'),bytes.fromhex('83c414'))),
        ('iob-owned-code-alias',code_alias),
        ('completion-wrong-guard-owner',lambda d:replace(d,'main-completion.bin',bytes.fromhex('33cd'),bytes.fromhex('33ce'))),
        ('missing-report-entry-global',missing_global)]
    for name,mutate in cases:
        directory=out/'negative'/name;directory.mkdir(parents=True,exist_ok=False)
        for path in out.iterdir():
            if path.is_file() and (path.suffix=='.bin' or path.name=='frame.manifest'):shutil.copyfile(path,directory/path.name)
        mutate(directory);result.append((name,directory))
    return result


CASE_NAMES=tuple(f'feature-selector-{i}-{j}' for i in range(6) for j in range(2))+(
    'trace-1','trace-wrap','trace-max','abandoned-7','abandoned-max',
    'deferred-one-byte-flush','immediate-projection-success','deferred-zero-write',
    'deferred-broken-pipe','deferred-partial-then-error')
RUNTIME_CASES=('zero-sp','low-sp','unaligned-sp','wrapping-sp','reversed-thread-range','outside-thread-range','module-stack-alias','missing-global','extra-global','wrong-options-low','wrong-options-high')
RUNTIME_REJECTIONS=len(RUNTIME_CASES)


def windows_reference(original,out,required):
    directory=original/'reported-native-windows'
    if directory.resolve()==out.resolve():
        if required:raise ValueError('Windows evidence cannot be current output')
        return None
    if not (directory/'native-reported-report.json').is_file():
        if required:raise ValueError('required retained Windows reported component missing')
        return None
    return directory


def verify_windows_component(directory,info,local_rust=None,local_harness=None):
    prior=json.loads((directory/'native-reported-report.json').read_text())
    for key in ['pe_sha256','source_sha256','object_sha256','independent_report_arguments','expected_physical_hex']:
        if prior.get(key)!=info[key]:raise ValueError('Windows reported original/expectation identity mismatch: '+key)
    source=(directory/'reported.rs').read_bytes();harness=(directory/'native-reported.rs').read_bytes()
    launch=json.loads((directory/'native-launch/launch.json').read_text())
    receipts=(directory/'case-receipts.txt').read_bytes()
    runtime_receipts=(directory/'runtime-receipts.txt').read_bytes()
    if (sha(source)!=prior.get('rust_sha256') or sha(harness)!=prior.get('harness_sha256')
        or sha(harness.replace(b'\r\n',b'\n'))!=prior.get('harness_lf_sha256')
        or sha(receipts)!=prior.get('receipt_sha256') or receipts.decode().splitlines()!=list(CASE_NAMES)
        or sha(runtime_receipts)!=prior.get('runtime_receipt_sha256') or runtime_receipts.decode().splitlines()!=list(RUNTIME_CASES)
        or (directory/'native.stdout').read_bytes().hex()!=info['expected_physical_hex'] or (directory/'native.stderr').read_bytes()
        or (directory/'native-launch/stdout').read_bytes().hex()!=info['expected_physical_hex'] or (directory/'native-launch/stderr').read_bytes()
        or prior.get('native_os')!='nt' or prior.get('whole_pe_translation_pairs')!=0
        or launch.get('stage')!='finished' or launch.get('timeout') is not False or launch.get('exit')!=0
        or launch.get('stdout_hex')!=info['expected_physical_hex'] or launch.get('stderr_hex')!=''
        or 'failure' in launch or sha((directory/'native-launch/program.bin').read_bytes())!=prior.get('native_sha256')
        or launch.get('executed_sha256')!=prior.get('native_sha256')):
        raise ValueError('Windows reported files/actual launch evidence failed')
    if (tuple(prior.get('executed_case_names',[]))!=CASE_NAMES or prior.get('runtime_rejections')!=RUNTIME_REJECTIONS
        or tuple(prior.get('executed_runtime_rejection_names',[]))!=RUNTIME_CASES or prior.get('native_windows_component_cases')!=len(CASE_NAMES)
        or tuple(r.get('case') for r in prior.get('rejection_cases',[]))!=REJECTION_NAMES
        or any(type(r.get('exit')) is not int or r['exit']==0 or not r.get('diagnostic') or 'panicked' in r['diagnostic']
               for r in prior.get('rejection_cases',[]))):
        raise ValueError('Windows reported conformance inventory differs')
    if local_rust is None:return None
    if source!=local_rust:raise ValueError('Windows/Linux reported generated Rust differs')
    if local_harness is None or harness.replace(b'\r\n',b'\n')!=local_harness.replace(b'\r\n',b'\n'):
        raise ValueError('Windows/Linux reported harness differs')
    return dict(cross_host_rust_identical=True,cross_host_same_original_pe=True,cross_host_harness_identical=True,
        native_windows_component_cases=len(CASE_NAMES),native_windows_report_sha256=sha((directory/'native-reported-report.json').read_bytes()))


def native_harness(info):
    def bytes_literal(raw):return '&['+','.join(str(n)+'u8' for n in raw)+'] as &[u8]'
    expected=bytes_literal(bytes.fromhex(info['expected_physical_hex']))
    selectors=[info['image_base']+info['connected_helpers']['context_selector']['comparison_stub_rva'],0]
    expected_by_trace=[bytes_literal(expected_output(independent_arguments(info,trace=value))[1]) for value in [4387,291,4294963491]]
    expected_by_abandoned=[bytes_literal(expected_output(independent_arguments(info,abandoned=value))[1]) for value in [7,0xffffffff]]
    notification=','.join(f'({a}u32,{k}u32,{v}u32)' for a,k,v in info['expected_notification_writes'])
    module=info['module_mapping']
    return f'''
fn main() {{
 use std::io::Write;
 let expected:&[u8]={expected};let mut receipts=Vec::<String>::new();let mut rejected=Vec::<String>::new();
 let verify=|o:&Outcome,entry:u32,main:u32,physical:&[u8]|{{
  assert_eq!(o.main_return,main);assert_eq!(o.returned[0],Some(main));assert_eq!(o.returned[4],Some(entry+4));
  for i in [1usize,2,3,5,6,7,8,9]{{assert_eq!(o.returned[i],None);}}
  assert_eq!(o.notification_writes,vec![{notification}]);assert_eq!(o.linked_registrations,vec![false,false,false]);
  assert_eq!(o.live,vec![false,false,false]);assert_eq!(o.report.logical_count(),Some((physical.len()-1)as u32));
  assert_eq!(o.report.pending_bytes(),physical);assert_eq!(o.report.written_bytes(),0);assert!(!o.report.stream_error());
 }};
 for (i,feature) in [i32::MIN,-1,0,1,2,i32::MAX].into_iter().enumerate(){{
  for (j,selector) in [{selectors[0]}u32,0].into_iter().enumerate(){{
   let mut o=run_reported(0x100000,0x13579bdf,feature,0,0xf0000,0x110000,selector,&[0],[0x24,0],ReportPolicy::Deferred,|_|panic!("implicit flush")).unwrap();
   verify(&o,0x100000,0,expected);let mut physical=Vec::new();
   assert_eq!(o.report.flush(|b|{{physical.extend_from_slice(b);Ok(b.len())}}).unwrap(),ReportFlush::Success);
   assert_eq!(physical,expected);assert!(o.report.pending_bytes().is_empty());assert_eq!(o.report.written_bytes(),expected.len());
   if i==0&&j==0{{std::io::stdout().lock().write_all(&physical).unwrap();}}
   receipts.push(format!("feature-selector-{{i}}-{{j}}"));
  }}
 }}
 for (initial,bytes,main,name) in [(1u32,{expected_by_trace[0]},1u32,"trace-1"),(1048576,{expected_by_trace[1]},0,"trace-wrap"),(u32::MAX,{expected_by_trace[2]},1,"trace-max")]{{
  let mut o=run_reported(0x200000,0x2468ace0,0,initial,0x1f0000,0x210000,0,&[0],[0x24,0],ReportPolicy::Deferred,|_|panic!("implicit flush")).unwrap();
  verify(&o,0x200000,main,bytes);let mut physical=Vec::new();assert_eq!(o.report.flush(|b|{{physical.extend_from_slice(b);Ok(b.len())}}).unwrap(),ReportFlush::Success);assert_eq!(physical,bytes);receipts.push(name.into());
 }}
 for (abandoned,bytes,name) in [(7u32,{expected_by_abandoned[0]},"abandoned-7"),(u32::MAX,{expected_by_abandoned[1]},"abandoned-max")]{{
  let mut o=run_reported(0x100000,0x13579bdf,0,0,0xf0000,0x110000,0,&[abandoned],[0x24,0],ReportPolicy::Deferred,|_|panic!("implicit flush")).unwrap();
  verify(&o,0x100000,1,bytes);let mut physical=Vec::new();assert_eq!(o.report.flush(|b|{{physical.extend_from_slice(b);Ok(b.len())}}).unwrap(),ReportFlush::Success);assert_eq!(physical,bytes);receipts.push(name.into());
 }}
 let deferred=||run_reported(0x100000,0x13579bdf,0,0,0xf0000,0x110000,0,&[0],[0x24,0],ReportPolicy::Deferred,|_|panic!("implicit flush")).unwrap();
 let mut o=deferred();let mut bytes=Vec::new();assert_eq!(o.report.flush(|b|{{bytes.push(b[0]);Ok(1)}}).unwrap(),ReportFlush::Success);assert_eq!(bytes,expected);assert_eq!(o.main_return,0);receipts.push("deferred-one-byte-flush".into());
 let mut bytes=Vec::new();let o=run_reported(0x100000,0x13579bdf,0,0,0xf0000,0x110000,0,&[0],[0x24,0],ReportPolicy::ImmediateProjection,|b|{{bytes.extend_from_slice(b);Ok(b.len())}}).unwrap();
 assert_eq!(bytes,expected);assert_eq!(o.main_return,0);assert!(o.report.pending_bytes().is_empty());assert_eq!(o.report.written_bytes(),expected.len());receipts.push("immediate-projection-success".into());
 for (mode,name) in [(0,"deferred-zero-write"),(1,"deferred-broken-pipe"),(2,"deferred-partial-then-error")]{{
  let mut o=deferred();let mut bytes=Vec::new();let flush=o.report.flush(|b|{{
   if mode==0{{Ok(0)}}else if mode==2&&bytes.is_empty(){{bytes.extend_from_slice(&b[..7]);Ok(7)}}else{{Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))}}
  }}).unwrap();
  assert_eq!(flush,ReportFlush::Failure);assert_eq!(o.main_return,0);assert_eq!(o.report.logical_count(),Some(275));assert!(o.report.stream_error());assert!(o.report.pending_bytes().is_empty());assert_eq!(o.report.written_bytes(),if mode==2{{7}}else{{0}});
  assert_eq!(bytes,if mode==2{{expected[..7].to_vec()}}else{{vec![]}});assert!(o.report.flush(|_|panic!("failed stream retried")).is_err());receipts.push(name.into());
 }}
 for (sp,name) in [(0u32,"zero-sp"),(256,"low-sp"),(0x100001,"unaligned-sp"),(0xfffffffcu32,"wrapping-sp")]{{assert!(run_reported(sp,0x13579bdf,0,0,0xf0000,0x110000,0,&[0],[0x24,0],ReportPolicy::Deferred,|_|panic!()).is_err());rejected.push(name.into());}}
 for (low,high,name) in [(0x110000,0xf0000,"reversed-thread-range"),(0x110000,0x120000,"outside-thread-range")]{{assert!(run_reported(0x100000,0x13579bdf,0,0,low,high,0,&[0],[0x24,0],ReportPolicy::Deferred,|_|panic!()).is_err());rejected.push(name.into());}}
 assert!(run_reported({module['end']}-4,0x13579bdf,0,0,{module['base']}-65536,{module['end']}+65536,0,&[0],[0x24,0],ReportPolicy::Deferred,|_|panic!()).is_err());rejected.push("module-stack-alias".into());
 for (globals,name) in [(&[][..],"missing-global"),(&[0u32,0][..],"extra-global")]{{assert!(run_reported(0x100000,0x13579bdf,0,0,0xf0000,0x110000,0,globals,[0x24,0],ReportPolicy::Deferred,|_|panic!()).is_err());rejected.push(name.into());}}
 for (options,name) in [([0u32,0],"wrong-options-low"),([0x24,1],"wrong-options-high")]{{assert!(run_reported(0x100000,0x13579bdf,0,0,0xf0000,0x110000,0,&[0],options,ReportPolicy::Deferred,|_|panic!()).is_err());rejected.push(name.into());}}
 let runtime_receipt=std::env::args_os().nth(2).expect("runtime receipt path");std::fs::write(runtime_receipt,rejected.join("\\n")+"\\n").unwrap();
 let receipt=std::env::args_os().nth(1).expect("receipt path");std::fs::write(receipt,receipts.join("\n")+"\n").unwrap();
}}
'''


def check(original,compiler,out,required=False):
    windows=windows_reference(original,out,required);out.mkdir(parents=True,exist_ok=False);info=prepare(original,out)
    if windows is not None:verify_windows_component(windows,info)
    source=out/'reported.rs';repeat=out/'reported-repeat.rs'
    command([compiler,out,source],'conversion',out,120);command([compiler,out,repeat],'repeat-conversion',out,120)
    if source.read_bytes()!=repeat.read_bytes():raise ValueError('reported source nondeterministic')
    harness=out/'native-reported.rs';harness.write_text(source.read_text()+native_harness(info))
    native=out/('native-reported.exe' if os.name=='nt' else 'native-reported')
    command(['rustc','--edition=2021',harness,'-o',native],'rustc',out,120)
    receipt=out/'case-receipts.txt';runtime_receipt=out/'runtime-receipts.txt'
    launched=execute([str(native),str(receipt),str(runtime_receipt)],out/'native.stdout',out/'native.stderr',out/'native-launch',
        {'pe_sha256':info['pe_sha256']},{'exit':0,'stdout_hex':info['expected_physical_hex'],'case_names':list(CASE_NAMES)},timeout=10)
    if launched.returncode or (out/'native.stdout').read_bytes().hex()!=info['expected_physical_hex'] or (out/'native.stderr').read_bytes():
        raise ValueError('reported native execution/conditional flush output failed')
    if receipt.read_text().splitlines()!=list(CASE_NAMES):raise ValueError('actual case receipt differs')
    if runtime_receipt.read_text().splitlines()!=list(RUNTIME_CASES):raise ValueError('actual runtime rejection receipt differs')
    rejections=[]
    for name,directory in mutation_directories(out):
        result=command([compiler,directory,directory/'rejected.rs'],name,directory,120,False);diagnostic=result.stderr.decode(errors='replace').strip()
        if result.returncode==0 or not diagnostic or 'panicked' in diagnostic:raise ValueError('report mutation did not reject safely: '+name)
        rejections.append(dict(case=name,exit=result.returncode,diagnostic=diagnostic))
    info['evidence_stage']='reported component executed under explicit stdio/flush preconditions; zero whole-PE translations'
    report=dict(info,kind='conditional original Main report/return component',rust_sha256=sha(source.read_bytes()),
        harness_sha256=sha(harness.read_bytes()),harness_lf_sha256=sha(harness.read_bytes().replace(b'\r\n',b'\n')),
        native_sha256=sha(native.read_bytes()),native_os=os.name,native_platform=platform.platform(),
        receipt_sha256=sha(receipt.read_bytes()),runtime_receipt_sha256=sha(runtime_receipt.read_bytes()),executed_runtime_rejection_names=list(RUNTIME_CASES),executed_case_names=list(CASE_NAMES),runtime_rejections=RUNTIME_REJECTIONS,
        rejection_cases=rejections,original_windows_baselines=1,conditional_native_stdout_comparisons=1,
        native_windows_component_cases=len(CASE_NAMES) if os.name=='nt' else 0,
        native_linux_component_cases=len(CASE_NAMES) if sys.platform.startswith('linux') else 0,
        cross_host_rust_identical=None,whole_pe_translation_pairs=0,
        explicit_entry_contract=dict(extra_globals_baseline=[0],stdio_options=[0x24,0],default_policy='Deferred',
            normal_exit_flush_proved=False,main_return_is_process_exit=False),
        case_provenance='15 inherited scalar scenarios; two explicit abandoned-state cases; two output-policy/partial-flush cases; three modeled flush-failure cases. These are not22 original Windows baselines.',
        logical_character_count=275,physical_stdout_bytes=276)
    if windows is not None:report.update(verify_windows_component(windows,info,source.read_bytes(),harness.read_bytes()))
    require_cross_host_result(report,required)
    if required and report.get('cross_host_harness_identical') is not True:raise ValueError('cross-host harness verification missing')
    (out/'native-reported-report.json').write_text(json.dumps(report,indent=2)+'\n');return report


class EvidenceGateTests(unittest.TestCase):
    """Synthetic gate records only: none counts as native execution evidence."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.directory=self.root/'reported-native-windows';self.directory.mkdir()
        self.info=dict(pe_sha256='original-pe',source_sha256='original-source',object_sha256='original-object',
            independent_report_arguments=list(range(17)),expected_physical_hex=b'expected\r\n'.hex())
        self.source=b'generated rust';self.harness=b'harness\n';self.native=b'owned test executable'
        (self.directory/'reported.rs').write_bytes(self.source);(self.directory/'native-reported.rs').write_bytes(self.harness)
        receipts=('\n'.join(CASE_NAMES)+'\n').encode();runtime=('\n'.join(RUNTIME_CASES)+'\n').encode()
        (self.directory/'case-receipts.txt').write_bytes(receipts);(self.directory/'runtime-receipts.txt').write_bytes(runtime)
        (self.directory/'native.stdout').write_bytes(bytes.fromhex(self.info['expected_physical_hex']));(self.directory/'native.stderr').write_bytes(b'')
        launch=self.directory/'native-launch';launch.mkdir();(launch/'program.bin').write_bytes(self.native)
        (launch/'stdout').write_bytes(bytes.fromhex(self.info['expected_physical_hex']));(launch/'stderr').write_bytes(b'')
        self.launch=dict(stage='finished',timeout=False,exit=0,stdout_hex=self.info['expected_physical_hex'],stderr_hex='',executed_sha256=sha(self.native))
        self.report=dict(self.info,rust_sha256=sha(self.source),harness_sha256=sha(self.harness),harness_lf_sha256=sha(self.harness),
            receipt_sha256=sha(receipts),runtime_receipt_sha256=sha(runtime),native_os='nt',whole_pe_translation_pairs=0,
            native_sha256=sha(self.native),executed_case_names=list(CASE_NAMES),runtime_rejections=RUNTIME_REJECTIONS,
            executed_runtime_rejection_names=list(RUNTIME_CASES),native_windows_component_cases=len(CASE_NAMES),
            rejection_cases=[dict(case=name,exit=1,diagnostic='independently expected rejection') for name in REJECTION_NAMES])
        self.save()
    def save(self):
        (self.directory/'native-reported-report.json').write_text(json.dumps(self.report))
        (self.directory/'native-launch/launch.json').write_text(json.dumps(self.launch))
    def verify(self):return verify_windows_component(self.directory,self.info,self.source,self.harness)
    def test_missing_and_self_reference_reject(self):
        with self.assertRaises(ValueError):windows_reference(self.root,self.directory,True)
        with self.assertRaises(ValueError):windows_reference(self.root/'missing',self.root/'other',True)
    def test_complete_synthetic_record_and_cross_host_bytes(self):
        self.assertTrue(self.verify()['cross_host_rust_identical'])
        with self.assertRaises(ValueError):verify_windows_component(self.directory,self.info,b'different rust',self.harness)
        with self.assertRaises(ValueError):verify_windows_component(self.directory,self.info,self.source,b'different harness')
    def test_original_identity_mutation_rejects(self):
        for key in ['pe_sha256','source_sha256','object_sha256']:
            with self.subTest(key=key):
                old=self.report[key];self.report[key]='changed';self.save()
                with self.assertRaises(ValueError):self.verify()
                self.report[key]=old
    def test_missing_execution_receipt_rejects_even_rehashed(self):
        for filename,key,names in [('case-receipts.txt','receipt_sha256',CASE_NAMES),('runtime-receipts.txt','runtime_receipt_sha256',RUNTIME_CASES)]:
            with self.subTest(filename=filename):
                path=self.directory/filename;old=path.read_bytes();changed=('\n'.join(names[:-1])+'\n').encode()
                path.write_bytes(changed);self.report[key]=sha(changed);self.save()
                with self.assertRaises(ValueError):self.verify()
                path.write_bytes(old);self.report[key]=sha(old)
    def test_raw_stdout_and_executable_tampering_reject(self):
        for name in ['native.stdout','native.stderr','native-launch/stdout','native-launch/stderr','native-launch/program.bin','reported.rs','native-reported.rs']:
            with self.subTest(name=name):
                path=self.directory/name;old=path.read_bytes();path.write_bytes(old+b'tampered')
                with self.assertRaises(ValueError):self.verify()
                path.write_bytes(old)
    def test_timeout_and_false_inventory_reject(self):
        self.launch['timeout']=True;self.save()
        with self.assertRaises(ValueError):self.verify()
        self.launch['timeout']=False;self.report['rejection_cases'][0]['exit']=0;self.save()
        with self.assertRaises(ValueError):self.verify()
    def test_windows_long_and_physical_newline_oracle(self):
        info=dict(report_symbol_rvas=dict(table_rva=86400,cleanup_rvas=[4096,4128,4160],restore_rva=4688,restore_target_rva=5029))
        values=independent_arguments(info);self.assertEqual(values[6:],[291,118,213,300,1,0,-1,-1,77,1,1])
        logical,physical=expected_output(values);self.assertEqual((len(logical),len(physical)),(275,276))
        self.assertEqual(physical.count(b'\r\n'),1);self.assertIn(b'"inner_cursor":-1',physical)


if __name__=='__main__':
    if '--selftest' in sys.argv:
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceGateTests))
        raise SystemExit(0 if result.wasSuccessful() else 1)
    parser=argparse.ArgumentParser();parser.add_argument('original',type=Path);parser.add_argument('compiler',type=Path)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--prepare-only',action='store_true')
    parser.add_argument('--require-windows-component',action='store_true');args=parser.parse_args()
    if args.prepare_only:
        if args.require_windows_component:parser.error('prepare-only cannot verify cross-host execution')
        args.output.mkdir(parents=True,exist_ok=False);info=prepare(args.original.resolve(),args.output.resolve())
        print(json.dumps(dict(stage='prepared only',pe_sha256=info['pe_sha256'],arguments=info['independent_report_arguments'],whole_pe_translation_pairs=0)))
    else:
        r=check(args.original.resolve(),args.compiler.resolve(),args.output.resolve(),args.require_windows_component)
        print(json.dumps(dict(pe_sha256=r['pe_sha256'],rust_sha256=r['rust_sha256'],executed_cases=len(CASE_NAMES),runtime_rejections=RUNTIME_REJECTIONS,compile_rejections=len(r['rejection_cases']),cross_host_rust_identical=r['cross_host_rust_identical'],whole_pe_translation_pairs=0)))
