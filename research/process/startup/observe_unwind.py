"""Bounded observer of unchanged authored PE; never an ordinary baseline.

No before/after-unlink policy is an expected-value oracle: that disputed runtime
behavior is recorded. Source outputs and observer cleanup have independent gates.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys

from check_unwind import verify_evidence
from frame_binding import write_evidence,instructions
from inventory import mapped_bytes
from module_identity import identify,version

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[2]/'corpus'))
from launch import execute

SITE_NAMES={1:'handler-entry',2:'handler-return',3:'rtl-call',4:'rtl-resume',
    5:'before-temporary-fs-install',6:'local-loop-head-after-fs-install',7:'before-temporary-fs-pop',
    8:'after-temporary-fs-pop',9:'notification-code-stored',10:'notification-target-stored',
    11:'notification-frame-stored',12:'cleanup-bridge-call',13:'selected-landing',
    14:'after-manual-restoration-capture',15:'after-main-normal-fs-restore',
    16:'nested-handler-entry',17:'local-unwind-entry'}


def sha(raw):return hashlib.sha256(raw).hexdigest()


def prepare(original,out):
    report,pe,base,table=verify_evidence(original)
    evidence=write_evidence(original,out/'binding')
    blocks={b['name']:b for b in evidence['fragments']}
    index=instructions((original/'disasm.txt').read_text(),pe)
    dispatch=evidence['dispatch'];sites=[]
    def site(kind,rva):
        if rva not in index or not 1<=kind<=24:raise ValueError('observer site lacks original instruction boundary')
        row=index[rva];raw=bytes.fromhex(row['code_hex'])
        if not raw or raw[0]==0xcc or mapped_bytes(pe,base+rva,len(raw))!=raw:
            raise ValueError('observer breakpoint does not bind original executable bytes')
        sites.append(dict(id=kind,name=SITE_NAMES[kind],rva=rva,instruction_hex=raw.hex()))
    def only(block,encoding):
        matches=[r for r in blocks[block]['instructions'] if r['code_hex']==encoding]
        if len(matches)!=1:raise ValueError('observer effect site is ambiguous: '+block)
        return matches[0]
    site(1,dispatch['handler_rva'])
    returns=blocks['original-handler-complete']['return_sites']
    if len(returns)!=1 or returns[0]['pop_bytes']!=0:raise ValueError('original handler return contract changed')
    site(2,returns[0]['rva']);site(3,dispatch['rtl_unwind_call_rva']);site(4,dispatch['rtl_unwind_resume_rva'])
    for before,after,encoding in [(5,6,'64892500000000'),(7,8,'648f0500000000')]:
        row=only('original-local-unwind',encoding);site(before,row['rva']);site(after,row['rva']+row['size'])
    for kind,encoding in [(9,'894b08'),(10,'894304'),(11,'896b0c')]:
        row=only('original-notification',encoding);site(kind,row['rva']+row['size'])
    site(12,blocks['original-cleanup-bridge']['rva'])
    site(13,blocks['main-selected-handler-0']['rva'])
    site(14,blocks['selected-through-capture']['capture_end_rva'])
    row=only('main-normal-epilog','64890d00000000');site(15,row['rva']+row['size'])
    site(16,dispatch['nested_handler_rva']);site(17,blocks['original-local-unwind']['rva'])
    if len({s['rva'] for s in sites})!=len(sites):raise ValueError('overlapping observer breakpoints')
    header=struct.unpack_from('<I',pe,60)[0];image_size=struct.unpack_from('<I',pe,header+24+56)[0]
    lines=[' '.join(str(x) for x in [image_size,dispatch['handler_rva'],dispatch['nested_handler_rva'],
        dispatch['notification_record_rva'],dispatch['rtl_unwind_iat_rva']])]
    lines += [f"{s['id']} {s['rva']} {int(s['instruction_hex'][:2],16)}" for s in sites]
    (out/'sites.txt').write_text('\n'.join(lines)+'\n')
    plan=dict(kind='instrumented same-artifact observer plan; not ordinary baseline or translation',
        pe_sha256=report['pe_sha256'],source_sha256=report['source_sha256'],
        object_sha256=evidence['object_sha256'],image_size=image_size,sites=sites,
        limits=dict(events=2048,site_hits=256,chain_nodes=12,modules=64,seconds=20),
        expectations=dict(original_stdout_observation=report['observation'],original_exit=0,original_stderr_hex='',
            unlink_timing='measurement, not presupposed',callback_flags='measurement, not presupposed'),
        source_unchanged=True,whole_pe_translation_pairs=0)
    (out/'plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    return plan


def parse_events(raw,expected_success,plan=None):
    if len(raw)>2*1024*1024:raise ValueError('observer output budget')
    rows=[json.loads(line) for line in raw.decode('utf-8').splitlines() if line]
    if any(not isinstance(row,dict) for row in rows):raise ValueError('observer event must be an object')
    if not rows or rows[-1].get('kind')!='summary' or sum(r.get('kind')=='summary' for r in rows)!=1:
        raise ValueError('observer has no unique terminal cleanup summary')
    summary=rows[-1]
    if (summary.get('success') is not expected_success or summary.get('cleanup_ok') is not True
            or summary.get('child_exited') is not True
            or type(summary.get('events')) is not int or not 0<summary['events']<=2048
            or type(summary.get('hits')) is not int or not 0<summary['hits']<=256
            or summary.get('child_exit')!=(0 if expected_success else 125)
            or summary.get('interval_complete') is not expected_success
            or summary.get('breakpoints_restored') is not True):
        raise ValueError('observer failed owned-child cleanup/completion contract')
    sites=[r for r in rows if r.get('kind')=='site']
    if expected_success:
        if [r.get('sequence') for r in sites]!=list(range(1,len(sites)+1)) or summary['hits']!=len(sites):
            raise ValueError('observer site sequence/count differs')
        required=set(SITE_NAMES)-{16}
        if not required.issubset({r.get('site') for r in sites}):raise ValueError('observer did not reach all required original sites')
    intervals=[(i,row) for i,row in enumerate(rows) if row.get('kind')=='interval-complete']
    if expected_success:
        if len(intervals)!=1:raise ValueError('observer interval completion missing or duplicated')
        at,marker=intervals[0]
        if (marker.get('last_site')!=15 or marker.get('hits')!=len(sites)
                or marker.get('breakpoints_restored') is not True
                or marker.get('trap_flag_cleared') is not True
                or not sites or sites[-1]['site']!=15
                or any(row.get('kind')=='site' for row in rows[at+1:])):
            raise ValueError('observer interval did not restore all instrumentation')
    elif intervals:raise ValueError('injected first-hit failure cannot complete interval')
    for i,row in enumerate(rows):
        if row.get('kind')=='teardown-thread' and (not intervals or i<=intervals[0][0]):
            raise ValueError('unobserved thread arrived before completed interval')
    allowed={'module','site','exception','summary','interval-complete','teardown-thread'}
    if any(not isinstance(row,dict) or row.get('kind') not in allowed for row in rows):
        raise ValueError('unknown observer event')
    expected={site['id']:site for site in plan['sites']} if plan else None
    for row in sites:
        def word(value):return type(value) is int and 0<=value<=0xffffffff
        fields=['site','rva','image_base','teb','stack_limit','stack_base','fs_head',
            'eax','ecx','edx','ebx','esp','ebp','esi','edi','eflags','rtl_address']
        if any(not word(row.get(key)) for key in fields) or row['site'] not in SITE_NAMES:
            raise ValueError('invalid observer scalar/site identity')
        if expected is not None and (row['site'] not in expected or row['rva']!=expected[row['site']]['rva']):
            raise ValueError('observer site differs from original instruction binding')
        low,high=row['stack_limit'],row['stack_base']
        if not low<high or not low<=row['esp']<high:raise ValueError('invalid observed thread stack')
        for key,n in [('nlg',4),('record_prefix',4 if row['site'] in (1,2,16) else 0),
                      ('stack_words',5 if row['site'] in (1,2,16) else 4 if row['site'] in (3,4,17) else 0)]:
            values=row.get(key)
            if not isinstance(values,list) or len(values)!=n or not all(word(v) for v in values):
                raise ValueError('incomplete observed argument/record state')
        nodes=row.get('chain')
        if not isinstance(nodes,list) or len(nodes)>12:raise ValueError('observed chain budget')
        cursor=row['fs_head'];seen=set()
        for node in nodes:
            at=node.get('address');values=node.get('words')
            if (not word(at) or at!=cursor or at in seen or at%4 or not isinstance(values,list)
                    or len(values) not in (2,4,7) or not all(word(v) for v in values)
                    or not low<=at or at+4*len(values)>high):
                raise ValueError('invalid observed chain ownership/link/range')
            seen.add(at);cursor=values[0]
        if cursor!=0xffffffff:raise ValueError('observed chain is incomplete')
    return rows


def bind_runtime_modules(rows):
    result=[]
    for row in rows:
        if row.get('kind')!='module':continue
        path=Path(bytes.fromhex(row['path_hex']).decode('ascii'))
        data=path.read_bytes()
        metadata=identify(data,0,row['machine'],row['timestamp'],row['size'])
        metadata.update(base=row['base'],path=str(path))
        try:metadata['file_version']=version(path)
        except (ValueError,OSError):metadata['file_version']=None
        result.append(metadata)
    if not result or len(result)>65:raise ValueError('loaded module inventory unavailable')
    addresses={row['rtl_address'] for row in rows if row.get('kind')=='site'}
    if len(addresses)!=1:raise ValueError('RtlUnwind IAT target changed during observed interval')
    address=addresses.pop()
    owners=[item for item in result if item['base']<=address<item['base']+item['image_size']]
    if len(owners)!=1:raise ValueError('resolved RtlUnwind target lacks unique loaded module')
    owner=owners[0]
    target=identify(Path(owner['path']).read_bytes(),address-owner['base'],owner['machine'],owner['timestamp'],owner['image_size'])
    owner['observed_rtl_unwind_target']=dict(address=address,**target)
    return result


def summarize(rows,plan):
    sites=[r for r in rows if r.get('kind')=='site']
    by_id={i:[r for r in sites if r['site']==i] for i in SITE_NAMES}
    before=by_id[3];after=by_id[4]
    if len(before)!=1 or len(after)!=1:raise ValueError('original RtlUnwind call/resume multiplicity changed')
    call,resume=before[0],after[0]
    args=call['stack_words']
    if len(args)!=4 or args[1]!=call['image_base']+next(s['rva'] for s in plan['sites'] if s['id']==4):
        raise ValueError('observed TargetIp is not original wrapper resume')
    handlers=[]
    for row in by_id[1]+by_id[2]:
        if len(row['stack_words'])!=5 or len(row['record_prefix'])!=4:raise ValueError('handler observation lacks full argument/record prefix')
        handlers.append(dict(sequence=row['sequence'],phase=SITE_NAMES[row['site']],
            record=row['stack_words'][1],establisher=row['stack_words'][2],context=row['stack_words'][3],
            dispatcher_context=row['stack_words'][4],flags=row['record_prefix'][1],code=row['record_prefix'][0],
            disposition=row['eax'] if row['site']==2 else None,fs_head=row['fs_head'],chain=row['chain']))
    handlers.sort(key=lambda r:r['sequence'])
    return dict(rtl_arguments=dict(target_frame=args[0],target_ip=args[1],record=args[2],return_value=args[3]),
        rtl_resume=dict(eax=resume['eax'],esp_before=call['esp'],esp_after=resume['esp'],
            ebp_before=call['ebp'],ebp_after=resume['ebp'],before_nonvolatile={k:call[k] for k in ['ebx','esi','edi']},
            after_nonvolatile={k:resume[k] for k in ['ebx','esi','edi']},fs_before=call['fs_head'],fs_after=resume['fs_head']),
        callbacks=handlers,notification_snapshots=[dict(sequence=r['sequence'],site=SITE_NAMES[r['site']],values=r['nlg']) for r in sites if r['site'] in [9,10,11]],
        chain_snapshots=[dict(sequence=r['sequence'],site=SITE_NAMES[r['site']],head=r['fs_head'],nodes=r['chain']) for r in sites],
        nested_handler_hits=len(by_id[16]),
        policy='Observed ordering only; no universal unlink-before/after contract inferred from this run')


def run(original,out):
    if os.name!='nt':raise ValueError('same-artifact observer requires genuine Windows x86 debugger APIs')
    out.mkdir(parents=True,exist_ok=False);plan=prepare(original,out)
    source=HERE.parents[2]/'tools'/'observe_unwind.c'
    # HERE parents[2] is repository root (startup/process/research).
    observer=out/'observe-unwind.exe'
    command=['cl','/nologo','/W4','/O2',str(source),'/Fe'+str(observer),'/Fo'+str(out/'observe-unwind.obj')]
    built=subprocess.run(command,capture_output=True,timeout=60)
    (out/'build.stdout').write_bytes(built.stdout);(out/'build.stderr').write_bytes(built.stderr)
    if built.returncode:raise RuntimeError('observer compilation failed')
    binary=original/'unwind.exe';digest=sha(binary.read_bytes())
    if digest!=plan['pe_sha256']:raise ValueError('original PE changed after evidence preparation')
    records=[]
    for label,mode,expected in [('observed',[],True),('cleanup-failure',['fail-after-first-hit'],False)]:
        if sha(binary.read_bytes())!=plan['pe_sha256']:raise ValueError('original PE changed before observed run')
        directory=out/label;directory.mkdir()
        result=execute([str(observer),str(binary),str(out/'sites.txt'),str(directory/'child.stdout'),str(directory/'child.stderr'),*mode],
            directory/'observer.stdout',directory/'observer.stderr',directory/'launch',
            dict(original_pe_sha256=digest,observer_source_sha256=sha(source.read_bytes())),
            dict(exit=0 if expected else 125,instrumented=True,cleanup_required=True),timeout=30)
        if result.returncode!=(0 if expected else 125):raise ValueError('observer exit contract failed: '+label)
        rows=parse_events((directory/'observer.stdout').read_bytes(),expected,plan)
        if sha(binary.read_bytes())!=digest:raise ValueError('original PE file changed during observation')
        if expected:
            actual=json.loads((directory/'child.stdout').read_bytes())
            if actual!=plan['expectations']['original_stdout_observation'] or (directory/'child.stderr').read_bytes():
                raise ValueError('instrumented program differs from original ordinary baseline')
            modules=bind_runtime_modules(rows)
            observed=summarize(rows,plan)
            (directory/'analysis.json').write_text(json.dumps(observed,indent=2)+'\n')
        records.append(dict(label=label,exit=result.returncode,summary=rows[-1],stdout_sha256=sha((directory/'observer.stdout').read_bytes())))
    report=dict(plan,kind='separately instrumented original Windows run; zero translation pairs',
        platform=platform.platform(),observer_source_sha256=sha(source.read_bytes()),observer_sha256=sha(observer.read_bytes()),
        observer_build_command=command,vc_tools_version=os.environ.get('VCToolsVersion'),modules=modules,
        runs=records,observed=observed,
        caveats=['INT3 and temporary TF can perturb debugger/exception behavior; ordinary baseline is retained separately.',
            'Only this pinned Windows/module build and application-contained no-secondary-exception path are observed.',
            'Unknown original exceptions are passed to Windows; observer does not implement or suppress application handlers.',
            'Instrumentation ends after Main normal FS restoration; later CRT teardown threads are logged but not instrumented.',
            'Site6 is also a loop head: repeated hits do not imply repeated temporary FS installs.',
            'No general nested/collided unwind correctness or full CRT startup translation follows from these observations.'])
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(pe_sha256=digest,site_hits=records[0]['summary']['hits'],cleanup_failure_test=True,whole_pe_translation_pairs=0)))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('original',type=Path);parser.add_argument('output',type=Path)
    parser.add_argument('--prepare-only',action='store_true');args=parser.parse_args()
    if args.prepare_only:
        args.output.mkdir(parents=True,exist_ok=False);print(json.dumps(prepare(args.original.resolve(),args.output.resolve()),indent=2))
    else:run(args.original.resolve(),args.output.resolve())
