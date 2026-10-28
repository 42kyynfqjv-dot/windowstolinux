"""Original frame/filter/funclet composition, with all unproved cuts explicit.

The expected Windows values come from the frozen original observation. Numeric
stack/cookie/register inputs below are independent native test inputs, not a
recorded Windows CONTEXT or evidence of complete startup execution.
"""
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import shutil
import struct
import subprocess
import sys

from check_unwind import verify_evidence
from coff_binding import pe_sections
from frame_binding import write_evidence
from inventory import mapped_bytes

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[2]/'corpus'))
from launch import execute

EXPECTED_REJECTION_NAMES = (
    'malformed-frame-prefix', 'truncated-event-argument', 'guard-overwrite',
    'self-parent-eh4', 'filter-owner-slot', 'aliased-funclet-arguments',
    'cookie-identity', 'feature-identity', 'installer-protected-slot',
    'invalid-activation-level', 'truncated-restore', 'incomplete-target-instruction',
    'event-call-disagreement', 'wrong-direct-call-target', 'wrong-frame-order',
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def prepare(original,out):
    observed,pe,base,table = verify_evidence(original)
    evidence = write_evidence(original,out)
    blocks = {b['name']:b for b in evidence['fragments']}
    frames = {f['symbol']:f for f in evidence['frames']}
    lines = []
    common = {}
    for key,symbol in [('cookie','___security_cookie'),('handler','__except_handler4')]:
        values = {r['target_va'] for f in frames.values() for r in f['original_relocations']
                  if r['symbol'] == symbol and r['kind'] == 6 and r['addend'] == 0}
        if len(values) != 1:
            raise ValueError('original frames disagree about '+key)
        common[key] = values.pop()
        lines.append(f'{key} {common[key]}')
    lines.extend([f"trace {base+observed['dispatcher']['trace_rva']}",
                  f"feature {base+evidence['handler']['feature_word_rva']}"])
    inner = blocks['Inner-initialize']['instructions']
    arguments = []
    for instruction in inner[-4:]:
        raw = bytes.fromhex(instruction['code_hex'])
        if len(raw) == 2 and raw[0] == 0x6a:
            arguments.append(struct.unpack('<b',raw[1:])[0]&0xffffffff)
        elif len(raw) == 5 and raw[0] == 0x68:
            arguments.append(struct.unpack('<I',raw[1:])[0])
        else:
            raise ValueError('original RaiseException arguments are not four immediate pushes')
    if arguments[:3] != [0,0,0]:
        raise ValueError('original event argument domain changed')
    event = arguments[3]
    frozen = json.loads((HERE/'unwind-frozen.json').read_text())
    if event != frozen['exception_code']:
        raise ValueError('original event instruction differs from frozen expectation')
    lines.append(f'event {event}')
    for name in ['main','Outer','Inner']:
        prolog = blocks[name+'-prolog']
        initialize = blocks[name+'-initialize']
        if prolog['rva']+prolog['size'] != initialize['rva']:
            raise ValueError('frame prefix would hide an omitted instruction interval')
        start = prolog['rva']
        size = prolog['size']+initialize['size']
        filename = name+'-prefix.bin'
        (out/filename).write_bytes(mapped_bytes(pe,base+start,size))
        eh4 = frames['_'+name]['table']
        suffix = '- -'
        if name == 'main':
            activation = blocks['main-activate']
            gap = blocks['main-unproved-gap']
            if (gap['rva'] != start+size or gap['rva']+gap['size'] != activation['rva']
                    or len(frames['_main']['blocked_calls']) != 2):
                raise ValueError('main external-effect gap not retained explicitly')
            suffix = f"{base+activation['rva']} {activation['file']}"
        lines.append(f"frame {base+start} {filename} {base+eh4['rva']} {eh4['file']} {suffix}")
    def region(kind,block,filename=None):
        filename = filename or block['file']
        code = bytes.fromhex(block['code_hex'])
        if len(code) != block['size'] or sha(code) != block['sha256']:
            raise ValueError('region identity differs from original binding')
        (out/filename).write_bytes(code)
        lines.append(f"{kind} {base+block['rva']} {filename}")
    calls=[]
    for name in ['main','Outer','Inner']:
        if name=='main':
            activation=blocks['main-activate']
            call_rva=activation['rva']+activation['size']
            raw=mapped_bytes(pe,base+call_rva,5)
            targets=[r for r in frames['_main']['original_relocations']
                     if r['symbol']=='_Outer' and r['kind']==0x14 and r['addend']==0
                     and frames['_main']['rva']+r['offset']==call_rva+1]
            if (len(targets)!=1 or raw[0]!=0xe8
                    or base+call_rva+5+struct.unpack('<i',raw[1:])[0]!=targets[0]['target_va']
                    or targets[0]['target_va']!=base+frames['_Outer']['rva']):
                raise ValueError('main-to-Outer call not bound to original contiguous instructions')
        else:
            call=frames['_'+name]['blocked_calls'][0]
            call_rva=call['rva'];raw=bytes.fromhex(call['code_hex'])
            prefix=blocks[name+'-initialize']
            if prefix['rva']+prefix['size']!=call_rva or mapped_bytes(pe,base+call_rva,len(raw))!=raw:
                raise ValueError('original nested/event call is not contiguous with prefix')
        block=dict(file=name+'-call.bin',rva=call_rva,size=len(raw),code_hex=raw.hex(),sha256=sha(raw))
        region('call',block)
        calls.append(block)
    raise_call=frames['_Inner']['blocked_calls'][0]
    if raise_call.get('import')!=['kernel32.dll','RaiseException']:
        raise ValueError('original event IAT binding changed')
    lines.append(f"raise-iat {base+raise_call['target_rva']}")
    for block in evidence['fragments']:
        if '-filter-' in block['name']:
            region('filter',block)
        elif '-finally-' in block['name']:
            region('funclet',block)
        elif '-selected-handler-' in block['name']:
            region('landing',block)
    for block in observed['cleanups']:
        region('cleanup',block)
    region('dispatcher',observed['dispatcher'])
    scope = dict(file='scope.bin',rva=observed['table_rva'],size=len(table),code_hex=table.hex(),sha256=sha(table))
    region('dispatch-table',scope)
    region('normalizer',blocks['event-normalizer'])
    region('installer',blocks['exception-pair-installer'])
    region('restore',observed['restore'])
    target_rva = observed['restore_target_rva']
    target = mapped_bytes(pe,base+target_rva,15)
    region('target',dict(file='target.bin',rva=target_rva,size=len(target),code_hex=target.hex(),sha256=sha(target)))
    globals_by_va = {}
    owner_offsets = {}
    for owner in ['_Outer','_Inner']:
        frame = frames[owner]
        for name in frame['cleanup_fragments']:
            block = blocks[name]
            instructions = block['instructions']
            # Original cdecl call's arguments are built by these LEA/PUSH pairs.
            lea = [bytes.fromhex(instructions[i]['code_hex']) for i in [0,2]]
            if any(len(raw) != 3 or raw[:2] != b'\x8d\x45' for raw in lea) or any(instructions[i]['code_hex'] != '50' for i in [1,3]):
                raise ValueError('original finally argument construction changed')
            offsets = [struct.unpack('<b',raw[2:])[0] for raw in lea]
            if owner in owner_offsets and owner_offsets[owner] != offsets:
                raise ValueError('shared owner has inconsistent original finally arguments')
            owner_offsets[owner] = offsets  # local then cursor, cdecl push order.
            for relocation in frame['original_relocations']:
                at = frame['rva']+relocation['offset']
                if block['rva'] <= at < block['rva']+block['size'] and relocation['kind'] == 6:
                    if relocation['addend'] != 0:
                        raise ValueError('unexpected original funclet global addend')
                    va = relocation['target_va']
                    if va in globals_by_va and globals_by_va[va] != relocation['symbol']:
                        raise ValueError('aliased original output globals')
                    globals_by_va[va] = relocation['symbol']
    expected_by_symbol = {'_inner_result':frozen['expected_observation']['inner'],
        '_outer_result':frozen['expected_observation']['outer'],
        '_inner_cursor_result':frozen['expected_observation']['inner_cursor']&0xffffffff,
        '_outer_cursor_result':frozen['expected_observation']['outer_cursor']&0xffffffff}
    if set(globals_by_va.values()) != set(expected_by_symbol):
        raise ValueError('original output-global inventory changed')
    _,sections = pe_sections(pe)
    ordered_globals = []
    for va,symbol in sorted(globals_by_va.items()):
        maps = [s for s in sections if base+s['rva'] <= va and va+4 <= base+s['rva']+s['virtual']]
        if len(maps) != 1 or not maps[0]['flags']&0x80000000 or maps[0]['flags']&0x20000000:
            raise ValueError('output global lacks complete unique writable ownership')
        lines.append(f'global {va}')
        ordered_globals.append(dict(va=va,symbol=symbol,expected=expected_by_symbol[symbol]))
    main_stores = frames['_main']['initializer_stores']
    selected = [s for s in main_stores if s['value'] == frozen['expected_observation']['selected']]
    if len(selected) != 1:
        raise ValueError('independent selected-local initializer is ambiguous')
    info = dict(pe_sha256=observed['pe_sha256'],source_sha256=observed['source_sha256'],
        object_sha256=evidence['object_sha256'],image_base=base,
        event_code_from_instructions=event,globals=ordered_globals,
        original_calls=calls,raise_exception_iat_va=base+raise_call['target_rva'],
        owner_offsets=owner_offsets,selected_local_offset=selected[0]['frame_offset'],
        restore_target_va=base+target_rva,
        selection_target_va=base+frames['_main']['table']['rows'][0]['handler_rva'],
        windows_observed=frozen['expected_observation'],original_report_platform=observed['platform'],
        cuts=evidence['cuts'],main_gap=blocks['main-unproved-gap'],handler=evidence['handler'])
    (out/'frame.manifest').write_text('\n'.join(lines)+'\n')
    (out/'frame-input-provenance.json').write_text(json.dumps(info,indent=2)+'\n')
    return info


def command(command,label,out,timeout=30,expect_success=True):
    try:
        result = subprocess.run([str(x) for x in command],capture_output=True,timeout=timeout)
    except subprocess.TimeoutExpired as error:
        (out/(label+'.stdout')).write_bytes(error.stdout or b'')
        (out/(label+'.stderr')).write_bytes(error.stderr or b'')
        raise
    (out/(label+'.stdout')).write_bytes(result.stdout)
    (out/(label+'.stderr')).write_bytes(result.stderr)
    if expect_success and result.returncode:
        raise RuntimeError(label+': '+result.stderr.decode(errors='replace'))
    return result


def rejection_checks(compiler,out):
    """Change one proven boundary at a time; never execute modified images."""
    def replace_bytes(directory,name,needle,replacement):
        path=directory/name
        data=path.read_bytes()
        if data.count(needle)!=1:
            raise ValueError('negative case needs a unique original byte binding')
        path.write_bytes(data.replace(needle,replacement,1))
    def set_manifest_number(directory,key,delta):
        path=directory/'frame.manifest'
        lines=path.read_text().splitlines()
        found=[i for i,line in enumerate(lines) if line.startswith(key+' ')]
        if len(found)!=1:
            raise ValueError('negative case singleton is ambiguous')
        fields=lines[found[0]].split();fields[1]=str(int(fields[1])+delta)
        lines[found[0]]=' '.join(fields)
        path.write_text('\n'.join(lines)+'\n')
    def truncate(directory,name):
        path=directory/name;path.write_bytes(path.read_bytes()[:-1])
    def bad_target(directory):
        path=directory/'target.bin';path.write_bytes(path.read_bytes()[:1])
    def wrong_call(directory):
        path=directory/'main-call.bin';data=path.read_bytes()
        if len(data)!=5 or data[0]!=0xe8:raise ValueError('negative call binding')
        displacement=(struct.unpack('<I',data[1:])[0]+1)&0xffffffff
        path.write_bytes(data[:1]+struct.pack('<I',displacement))
    def wrong_frame_order(directory):
        path=directory/'frame.manifest';lines=path.read_text().splitlines()
        frames=[i for i,line in enumerate(lines) if line.startswith('frame ')]
        if len(frames)!=3:raise ValueError('negative frame count')
        lines[frames[1]],lines[frames[2]]=lines[frames[2]],lines[frames[1]]
        path.write_text('\n'.join(lines)+'\n')
    cases=[
        ('malformed-frame-prefix',lambda d:replace_bytes(d,'main-prefix.bin',bytes.fromhex('558bec'),bytes.fromhex('0f0bec'))),
        ('truncated-event-argument',lambda d:truncate(d,'Inner-prefix.bin')),
        ('guard-overwrite',lambda d:replace_bytes(d,'main-prefix.bin',bytes.fromhex('c78500fdffff2c010000'),bytes.fromhex('c785e4ffffff2c010000'))),
        ('self-parent-eh4',lambda d:replace_bytes(d,'main-eh4.bin',bytes.fromhex('feffffff'),bytes.fromhex('00000000'))),
        ('filter-owner-slot',lambda d:replace_bytes(d,'main-filter-0.bin',bytes.fromhex('8b55ec'),bytes.fromhex('8b55f0'))),
        ('aliased-funclet-arguments',lambda d:replace_bytes(d,'Inner-finally-1.bin',bytes.fromhex('8d45e0'),bytes.fromhex('8d45e4'))),
        ('cookie-identity',lambda d:set_manifest_number(d,'cookie',4)),
        ('feature-identity',lambda d:set_manifest_number(d,'feature',4)),
        ('installer-protected-slot',lambda d:replace_bytes(d,'exception-pair-installer.bin',bytes.fromhex('8943fc'),bytes.fromhex('8943f8'))),
        ('invalid-activation-level',lambda d:replace_bytes(d,'main-activate.bin',bytes.fromhex('c745fc00000000'),bytes.fromhex('c745fcffffffff'))),
        ('truncated-restore',lambda d:truncate(d,'Restore.bin')),
        ('incomplete-target-instruction',bad_target),
        ('event-call-disagreement',lambda d:set_manifest_number(d,'event',1)),
        ('wrong-direct-call-target',wrong_call),
        ('wrong-frame-order',wrong_frame_order),
    ]
    if tuple(name for name,_ in cases)!=EXPECTED_REJECTION_NAMES:
        raise ValueError('rejection contract differs from implemented checks')
    results=[]
    negatives=out/'rejections';negatives.mkdir()
    for name,mutate in cases:
        directory=negatives/name;directory.mkdir()
        for path in out.glob('*.bin'):
            shutil.copyfile(path,directory/path.name)
        shutil.copyfile(out/'frame.manifest',directory/'frame.manifest')
        mutate(directory)
        result=command([compiler,directory,directory/'rejected.rs'],'conversion',directory,expect_success=False)
        if result.returncode==0 or b'panicked' in result.stderr:
            raise ValueError('unsafe frame case accepted or compiler panicked: '+name)
        results.append(dict(case=name,exit=result.returncode,diagnostic=result.stderr.decode(errors='replace').strip()))
    return results


def windows_reference(original,out,required):
    windows=original/'frame-native-windows'
    if windows.resolve()==out.resolve():
        if required:
            raise ValueError('required Windows component cannot be its own current output')
        return None
    if not (windows/'native-frame-report.json').is_file():
        if required:
            raise ValueError('required retained Windows component report is missing')
        return None
    return windows


def verify_windows_files(windows,info):
    prior=json.loads((windows/'native-frame-report.json').read_text())
    for key in ['pe_sha256','source_sha256','object_sha256']:
        if prior.get(key)!=info[key]:
            raise ValueError('native Windows component used a different original '+key)
    original_rust=(windows/'frame.rs').read_bytes()
    if sha(original_rust)!=prior.get('rust_sha256'):
        raise ValueError('native Windows generated Rust lacks actual file provenance')
    if sha((windows/'native-frame.rs').read_bytes())!=prior.get('harness_sha256'):
        raise ValueError('native Windows harness differs from retained provenance')
    launch=json.loads((windows/'native-launch/launch.json').read_text())
    if (prior.get('native_os')!='nt'
            or launch.get('stage')!='finished' or launch.get('timeout') is not False
            or launch.get('exit')!=0 or 'failure' in launch
            or launch.get('stdout_hex')!='' or launch.get('stderr_hex')!=''
            or sha((windows/'native-launch/program.bin').read_bytes())!=prior.get('native_sha256')
            or launch.get('executed_sha256')!=prior.get('native_sha256')):
        raise ValueError('native Windows component completion evidence is incomplete')
    return prior,original_rust


def verify_windows_component(windows,info,local_rust=None):
    prior,original_rust=verify_windows_files(windows,info)
    if (prior.get('native_feature_cases')!=6 or prior.get('native_initial_trace_cases')!=3
            or prior.get('native_runtime_rejections')!=5
            or tuple(row.get('case') for row in prior.get('rejection_cases',[]))!=EXPECTED_REJECTION_NAMES
            or any(type(row.get('exit')) is not int or row['exit']==0 or not row.get('diagnostic')
                   or 'panicked' in row['diagnostic'] for row in prior.get('rejection_cases',[]))):
        raise ValueError('native Windows component conformance contract differs')
    if local_rust is not None and original_rust!=local_rust:
        raise ValueError('cross-host generated Rust differs')
    if local_rust is None:
        return None  # Preflight establishes retained evidence, not cross-host equality.
    return dict(native_windows_component_cases=9,
        cross_host_rust_identical=True,cross_host_same_original_pe=True,
        native_windows_report_sha256=sha((windows/'native-frame-report.json').read_bytes()))


def require_cross_host_result(report,required):
    if required and (report.get('cross_host_rust_identical') is not True
                     or report.get('cross_host_same_original_pe') is not True):
        raise ValueError('required Windows cross-host verification did not complete')


def check(original,compiler,out,require_windows_component=False):
    windows=windows_reference(original,out,require_windows_component)
    out.mkdir(parents=True,exist_ok=False)
    info = prepare(original,out)
    if windows is not None:
        verify_windows_component(windows,info)
    source = out/'frame.rs'
    command([compiler,out,source],'conversion',out)
    second = out/'frame-repeat.rs'
    command([compiler,out,second],'repeat-conversion',out)
    if source.read_bytes() != second.read_bytes():
        raise ValueError('original fragment conversion is not deterministic')
    rejections=rejection_checks(compiler,out)
    expectation = info['windows_observed']
    target = info['restore_target_va']
    globals_expected = ','.join('Some('+str(g['expected'])+'u32)' for g in info['globals'])
    inner_local,inner_cursor = info['owner_offsets']['_Inner']
    outer_local,outer_cursor = info['owner_offsets']['_Outer']
    harness = f'''
fn main() {{
  let saved=[77u32,11,12,13,32768,33024,16,17,{target},514];
  let current=[1u32,2,3,40,4096,8192,60,70,123,514];
  for feature in [i32::MIN,-1,0,1,2,i32::MAX] {{
    let o=run_fragments(0x100000,0x13579bdf,saved,current,feature,0).unwrap();
    assert_eq!(o.trace,{expectation['trace']});
    assert_eq!(o.globals,vec![{globals_expected}]);
    let field=|frame:usize,offset:i32| o.frame_words[frame][o.offsets[frame].iter().position(|&at|at==offset).unwrap()];
    assert_eq!(field(0,{info['selected_local_offset']}),Some({expectation['selected']}));
    assert_eq!(field(1,{outer_local}),Some({expectation['outer']}));
    assert_eq!(field(2,{inner_local}),Some({expectation['inner']}));
    assert_eq!(field(1,{outer_cursor}),Some(u32::MAX));
    assert_eq!(field(2,{inner_cursor}),Some(u32::MAX));
    assert_eq!(o.cursors,vec![None,Some(-1),Some(-1)]);
    assert_eq!(o.live,vec![true,false,false]);
    assert_eq!(o.selected_frame,0);
    assert_eq!(o.selected_target,{info['selection_target_va']});
    assert_eq!(o.restored[0],Some(77));
    assert_eq!(o.restored[4],Some(saved[4]));
    assert_eq!(o.restored[5],Some(saved[5]));
    assert_eq!(o.restored[8],Some(saved[8]));
  }}
  for (initial,expected) in [(1u32,4387u32),(1048576,291),(u32::MAX,4294963491)] {{
    let o=run_fragments(0x100000,0x13579bdf,saved,current,0,initial).unwrap();
    assert_eq!(o.trace,expected);
    assert_eq!(o.globals,vec![{globals_expected}]);
  }}
  for bad_sp in [0u32,256,0x100001] {{
    assert!(run_fragments(bad_sp,0x13579bdf,saved,current,0,0).is_err());
  }}
  let mut debug=current;debug[9]|=0x100;
  assert!(run_fragments(0x100000,0x13579bdf,saved,debug,0,0).is_err());
  let mut wrong_target=saved;wrong_target[8]+=1;
  assert!(run_fragments(0x100000,0x13579bdf,wrong_target,current,0,0).is_err());
}}
'''
    (out/'native-frame.rs').write_text(source.read_text()+harness)
    native = out/('native-frame.exe' if os.name == 'nt' else 'native-frame')
    command(['rustc','--edition=2021',out/'native-frame.rs','-o',native],'rustc',out,60)
    result = execute([str(native)],out/'native.stdout',out/'native.stderr',out/'native-launch',
        {'pe_sha256':info['pe_sha256']},{'exit':0,'feature_cases':6,'independent_initial_trace_cases':3,'runtime_rejections':5},timeout=10)
    if result.returncode or (out/'native.stdout').read_bytes() or (out/'native.stderr').read_bytes():
        raise ValueError('native frame assertions failed or unexpected output')
    report = dict(kind='original frame/filter/funclet composition under explicit cuts; zero whole-PE pairs',
        **info,rust_sha256=sha(source.read_bytes()),harness_sha256=sha((out/'native-frame.rs').read_bytes()),
        native_sha256=sha(native.read_bytes()),deterministic_emission=True,
        native_feature_cases=6,native_initial_trace_cases=3,native_runtime_rejections=5,windows_baseline_cases=1,
        native_platform=platform.platform(),native_os=os.name,
        native_windows_component_cases=9 if os.name=='nt' else 0,
        native_linux_component_cases=9 if sys.platform.startswith('linux') else 0,
        whole_pe_translation_pairs=0,
        rejection_cases=rejections,
        synthetic_inputs=dict(entry_sp=1048576,cookie=324508639,
            saved=[77,11,12,13,32768,33024,16,17,target,514],
            current=[1,2,3,40,4096,8192,60,70,123,514],feature_values=[-2147483648,-1,0,1,2,2147483647]),
        comparison_limits=[
            'Six feature-word values are native-only independent cases; the original Windows feature word was not observed.',
            'Initial trace zero follows the authored static zero-initialization domain, not a separately printed Windows initial-state observation; three nonzero initial-trace cases are native-only tests.',
            'Numeric SP, cookie and complete register vectors are synthetic cut inputs, not recorded original Windows state.',
            'Main initializer and activation are separated by unproved memset/GetModuleHandleW effects; their composition is conditional on explicit frame preservation.',
            'Original filter selection target and later manual Restore target are different; this slice does not execute the selected landing or prove transfer between those targets.',
            'Exception delivery, borrowed predecessor lifetime, original handler-prefix external effects, FS teardown and whole startup remain unproved.'])
    if windows is not None:
        report.update(verify_windows_component(windows,info,source.read_bytes()))
    else:
        report['cross_host_rust_identical']=None
    require_cross_host_result(report,require_windows_component)
    (out/'native-frame-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('original',type=Path)
    parser.add_argument('compiler',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--prepare-only',action='store_true')
    parser.add_argument('--require-windows-component',action='store_true')
    args = parser.parse_args()
    if args.prepare_only:
        if args.require_windows_component:
            parser.error('--prepare-only cannot establish required cross-host verification')
        args.output.mkdir(parents=True,exist_ok=False)
        print(json.dumps(prepare(args.original.resolve(),args.output.resolve()),indent=2))
    else:
        check(args.original.resolve(),args.compiler.resolve(),args.output.resolve(),args.require_windows_component)
