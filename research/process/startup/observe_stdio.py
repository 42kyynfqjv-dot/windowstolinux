"""Bounded same-artifact CRT stdio observation, not translation or ordinary baseline.

The authored executable is unchanged. Three successful short/zero API results
are debugger scripts with NO physical write. The invalid-handle case invokes
real Windows WriteFile with one explicitly substituted argument. None establishes
arbitrary CRT, OS short-write, concurrent FILE or process-exit equivalence.
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

from check_reported import prepare as prepare_reported
from frame_binding import instructions
from coff_binding import import_at_iat
from inventory import mapped_bytes
from module_identity import identify,version
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[2]/'corpus'))
from launch import execute

# Preregistered before any instrumented Windows execution. These are evidence
# addresses of the frozen authored artifact, never production dispatch stencils.
SITES={
 1:('main-printf-call',0x1466,'e8b5000000'),
 2:('main-after-printf',0x146b,'83c448'),
 3:('main-return',0x151b,'c3'),
 4:('text-writefile-call',0xdcc2,'ff1580504100'),
 5:('text-after-writefile',0xdcc8,'85c0'),
 6:('text-return',0xdd00,'c3'),
 7:('low-level-return',0xe248,'c3'),
 8:('flush-entry',0x8420,'8bff'),
 9:('flush-return',0x8488,'c3'),
 10:('stdout-lock-call',0x4640,'ff154c504100'),
 11:('stdout-lock-return',0x4646,'5d'),
 12:('stdout-unlock-call',0x4654,'ff1550504100'),
 13:('stdout-unlock-return',0x465a,'5d'),
 14:('after-file-error-bit',0x846d,'83c8ff'),
 15:('after-flush-reset',0x844b,'85ff'),
}
CASES={
 'baseline':dict(mode=0,api='real Windows API',count=276,text_result=[0,276,1],logical=275,flush=0,error=False,physical='original'),
 'short-seven':dict(mode=1,api='scripted TRUE/count7; API not executed; no physical write',count=7,text_result=[0,7,1],logical=6,flush=0xffffffff,error=True,physical='empty'),
 'short-one':dict(mode=2,api='scripted TRUE/count1; API not executed; no physical write',count=1,text_result=[0,1,1],logical=0,flush=0xffffffff,error=True,physical='empty'),
 'zero-success':dict(mode=3,api='scripted TRUE/count0; API not executed; no physical write',count=0,text_result=[0,0,1],logical=0xffffffff,flush=0xffffffff,error=True,physical='empty'),
 'invalid-handle':dict(mode=4,api='real Windows API with scripted INVALID_HANDLE_VALUE argument',count=0,text_result=[6,0,1],logical=0xffffffff,flush=0xffffffff,error=True,physical='empty'),
}

def sha(raw):return hashlib.sha256(raw).hexdigest()

def prepare(original,out):
    bound=out/'original-binding';bound.mkdir()
    info=prepare_reported(original,bound);image=(original/'unwind.exe').read_bytes();base=info['image_base']
    index=instructions((original/'disasm.txt').read_text(),image);sites=[]
    for ident,(name,rva,encoding) in SITES.items():
        row=index.get(rva)
        if row is None or row['code_hex']!=encoding or mapped_bytes(image,base+rva,row['size'])!=bytes.fromhex(encoding):
            raise ValueError('stdio observation site differs from bound original instruction: '+name)
        sites.append(dict(id=ident,name=name,rva=rva,instruction_hex=encoding))
    identities={}
    for ident,expected in [(4,('kernel32.dll','WriteFile')),(10,('kernel32.dll','EnterCriticalSection')),(12,('kernel32.dll','LeaveCriticalSection'))]:
        raw=bytes.fromhex(SITES[ident][2]);iat=struct.unpack('<I',raw[2:])[0]
        found=import_at_iat(image,iat-base)
        if tuple(found)!=expected:raise ValueError('stdio import does not bind original API: '+str(found))
        identities[str(ident)]=dict(iat_rva=iat-base,import_identity=found)
    pe=struct.unpack_from('<I',image,60)[0];size=struct.unpack_from('<I',image,pe+24+56)[0]
    stdout=info['report_binding']['stdout_address']
    if mapped_bytes(image,stdout,56) is None:raise ValueError('stdout FILE object is not full mapped extent')
    lines=[f'{size} {stdout-base} {identities["4"]["iat_rva"]}']
    lines += [f'{s["id"]} {s["rva"]} {int(s["instruction_hex"][:2],16)}' for s in sites]
    (out/'sites.txt').write_text('\n'.join(lines)+'\n')
    frozen_raw=(HERE/'stdio-frozen.json').read_bytes();frozen=json.loads(frozen_raw)
    for observed,expected in zip(CASES.values(),frozen['windows_observer_cases'],strict=True):
        if observed['text_result']!=expected['worker'] or observed['logical']!=expected['lowlevel_u32'] or observed['flush']!=expected['flush_u32']:
            raise ValueError('observer differs from independent preregistered expectations')
    plan=dict(frozen_expectations_sha256=sha(frozen_raw),kind='frozen same-artifact stdio observer plan; zero translation pairs',
        pe_sha256=info['pe_sha256'],source_sha256=info['source_sha256'],object_sha256=info['object_sha256'],
        image_base=base,image_size=size,stdout_rva=stdout-base,sites=sites,imports=identities,
        original_stdout_hex=info['expected_physical_hex'],original_exit=0,original_stderr_hex='',
        cases=CASES,limits=dict(events=2048,site_hits=512,modules=64,seconds=20,request_bytes=8192),
        frozen_expectations='Original source output and static original CRT branches; printf/Main/flush ordering and lock snapshots are measured, not assumed.',
        mutation_scope='Original file unchanged; only own-child breakpoints/TF plus explicitly labelled API count/result or handle argument scripting.',
        whole_pe_translation_pairs=0)
    (out/'plan.json').write_text(json.dumps(plan,indent=2)+'\n');return plan

def parse_events(raw,label,plan,cleanup=False):
    if len(raw)>4*1024*1024:raise ValueError('stdio observer output budget')
    rows=[json.loads(line) for line in raw.decode().splitlines() if line]
    allowed={'module','site','injection','exception','summary','interval-complete','thread-created'}
    if not rows or any(not isinstance(r,dict) or r.get('kind') not in allowed for r in rows):raise ValueError('invalid observer event')
    if rows[-1]['kind']!='summary' or sum(r['kind']=='summary' for r in rows)!=1:raise ValueError('terminal observer summary missing')
    summary=rows[-1];success=not cleanup
    if (summary.get('success') is not success or summary.get('cleanup_ok') is not True or summary.get('child_exited') is not True
        or summary.get('child_exit')!=(125 if cleanup else 0) or summary.get('interval_complete') is not success
        or summary.get('breakpoints_restored') is not True or type(summary.get('events')) is not int
        or not 0<summary['events']<=2048 or type(summary.get('hits')) is not int or not 0<summary['hits']<=512):
        raise ValueError('stdio observer cleanup/completion contract')
    sites=[r for r in rows if r['kind']=='site'];markers=[(i,r) for i,r in enumerate(rows) if r['kind']=='interval-complete']
    if cleanup:
        if sites or markers or summary['hits']!=1:raise ValueError('first-hit cleanup failure proceeded')
        return rows
    if [s.get('sequence') for s in sites]!=list(range(1,len(sites)+1)) or len(sites)!=summary['hits']:raise ValueError('site execution receipts differ')
    if len(markers)!=1:raise ValueError('stdio interval incomplete')
    pos,marker=markers[0]
    if (marker.get('hits')!=len(sites) or marker.get('last_site')!=sites[-1]['site']
        or marker.get('breakpoints_restored') is not True or marker.get('trap_flag_cleared') is not True
        or any(r['kind']=='site' for r in rows[pos+1:])):raise ValueError('stdio instrumentation not restored')
    bindings={s['id']:s for s in plan['sites']}
    def word(value):return type(value) is int and 0<=value<=0xffffffff
    for s in sites:
        if s.get('site') not in bindings or s.get('rva')!=bindings[s['site']]['rva']:raise ValueError('observed instruction identity differs')
        for key in ['image_base','stack_limit','stack_base','eax','ecx','edx','ebx','esp','ebp','esi','edi','eflags','writefile_address','stdout_address','stream_argument','count_cell','count_value','write_calls']:
            if not word(s.get(key)):raise ValueError('invalid observed scalar: '+key)
        if not s['stack_limit']<=s['esp']<s['stack_base'] or s['stdout_address']!=s['image_base']+plan['stdout_rva']:raise ValueError('observed thread/object bounds')
        for key,n in [('stream_words',14),('arguments',5 if s['site']==4 else 2 if s['site'] in (8,9) else 1 if s['site'] in (10,12) else 0),('text_result',3 if s['site']==6 else 0)]:
            if not isinstance(s.get(key),list) or len(s[key])!=n or not all(word(v) for v in s[key]):raise ValueError('observed bounded state incomplete')
        payload=bytes.fromhex(s.get('request_hex',''))
        if len(payload)>8192 or (s['site']!=4 and payload):raise ValueError('unexpected buffer observation')
    injections=[r for r in rows if r['kind']=='injection'];mode=CASES[label]['mode']
    if mode==0:
        if injections:raise ValueError('baseline contains scripted result')
    else:
        if len(injections)!=1 or injections[0].get('mode')!=mode:raise ValueError('missing or duplicated API script')
        inj=injections[0]
        if mode<4:
            if inj.get('api_executed') is not False or inj.get('physical_bytes_written')!=0 or inj.get('count')!=CASES[label]['count']:raise ValueError('scripted result falsely represented as OS write')
        elif inj.get('api_executed') is not True or inj.get('argument')!='INVALID_HANDLE_VALUE':raise ValueError('invalid-handle real API effect missing')
    return rows

def summarize(rows,label,plan):
    sites=[r for r in rows if r['kind']=='site'];expected=CASES[label]
    by={i:[r for r in sites if r['site']==i] for i in SITES}
    def one(kind):
        if len(by[kind])!=1:raise ValueError('frozen stdio site multiplicity changed: '+SITES[kind][0])
        return by[kind][0]
    call,post,text,low=one(4),one(5),one(6),one(7)
    if call['request_hex']!=plan['original_stdout_hex'] or call['arguments'][2]!=276 or call['arguments'][4]!=0:raise ValueError('original complete text request differs')
    if post['eax']!=(0 if label=='invalid-handle' else 1) or (label!='invalid-handle' and post['count_value']!=expected['count']) or text['text_result']!=expected['text_result'] or low['eax']!=expected['logical']:
        raise ValueError('original CRT result differs from frozen static expectation')
    if post['esp']!=call['esp']+20 or post['count_cell']!=call['arguments'][3] or post['write_calls']!=1:
        raise ValueError('original stdcall/count ownership changed')
    flushes=[s for s in by[9] if s['stream_argument']==s['stdout_address'] and s['write_calls']==1]
    if len(flushes)!=1:raise ValueError('original stdout flush return missing or duplicated')
    flush=flushes[0]
    if flush['eax']!=expected['flush'] or bool(flush['stream_words'][3]&0x10)!=expected['error']:raise ValueError('original FILE error/flush result differs')
    if flush['stream_words'][0]!=flush['stream_words'][1] or flush['stream_words'][2]!=0:raise ValueError('original flush pointer/count reset missing')
    main=one(3);printf=one(2)
    if main['eax']!=0:raise ValueError('original source Main result changed')
    unlock=[s for s in by[13] if s['stream_argument']==s['stdout_address'] and s['sequence']>flush['sequence'] and s['stream_words'][10]==0]
    if not unlock:raise ValueError('original stdout final unlock not observed')
    return dict(label=label,api_class=expected['api'],requested_bytes=276,api_return=post['eax'],api_count=post['count_value'],
        text_result=text['text_result'],logical_return=low['eax'],flush_return=flush['eax'],file_error=bool(flush['stream_words'][3]&0x10),
        printf_return=printf['eax'],main_return=main['eax'],
        order=dict(printf_return=printf['sequence'],main_return=main['sequence'],writefile=call['sequence'],flush_return=flush['sequence'],unlock=unlock[-1]['sequence']),
        lock_observations=[dict(sequence=s['sequence'],site=SITES[s['site']][0],stream_argument=s['stream_argument'],lock_words=s['stream_words'][8:14]) for s in sites if s['site'] in (10,11,12,13)],
        caveat='Observed original CRT downstream control; scripted successful API counts do not constitute real OS short writes or establish caller-volatile register/LastError semantics.')

def modules(rows):
    result=[]
    for row in rows:
        if row['kind']!='module':continue
        path=Path(bytes.fromhex(row['path_hex']).decode('ascii'));data=path.read_bytes()
        item=identify(data,0,row['machine'],row['timestamp'],row['size']);item.update(base=row['base'],path=str(path))
        try:item['file_version']=version(path)
        except (OSError,ValueError):item['file_version']=None
        result.append(item)
    targets={r['writefile_address'] for r in rows if r['kind']=='site'}
    if len(targets)!=1 or not 1<=len(result)<=65:raise ValueError('loaded WriteFile identity incomplete')
    target=targets.pop();owners=[r for r in result if r['base']<=target<r['base']+r['image_size']]
    if len(owners)!=1:raise ValueError('WriteFile target lacks unique loaded module')
    owners[0]['observed_writefile_target']=dict(address=target,**identify(Path(owners[0]['path']).read_bytes(),target-owners[0]['base'],owners[0]['machine'],owners[0]['timestamp'],owners[0]['image_size']))
    return result

def run(original,out):
    if os.name!='nt':raise ValueError('stdio observation requires genuine Windows debugger APIs')
    out.mkdir(parents=True,exist_ok=False);plan=prepare(original,out)
    source=HERE.parents[2]/'tools/observe_stdio.c';observer=out/'observe-stdio.exe'
    command=['cl','/nologo','/W4','/O2',str(source),'/Fe'+str(observer),'/Fo'+str(out/'observe-stdio.obj')]
    built=subprocess.run(command,capture_output=True,timeout=60)
    (out/'build.stdout').write_bytes(built.stdout);(out/'build.stderr').write_bytes(built.stderr)
    if built.returncode:raise RuntimeError('stdio observer build failed')
    binary=original/'unwind.exe';results=[]
    for label in [*CASES,'cleanup-failure']:
        cleanup=label=='cleanup-failure';mode='baseline' if cleanup else label
        if sha(binary.read_bytes())!=plan['pe_sha256']:raise ValueError('original PE changed before instrumented run')
        d=out/label;d.mkdir();args=[str(observer),str(binary),str(out/'sites.txt'),str(d/'child.stdout'),str(d/'child.stderr'),mode]
        if cleanup:args.append('fail-after-first-hit')
        launched=execute(args,d/'observer.stdout',d/'observer.stderr',d/'launch',
            dict(original_pe_sha256=plan['pe_sha256'],observer_source_sha256=sha(source.read_bytes())),
            dict(exit=125 if cleanup else 0,instrumented=True,label=label),timeout=30)
        if launched.returncode!=(125 if cleanup else 0):raise ValueError('stdio observer failed: '+label)
        rows=parse_events((d/'observer.stdout').read_bytes(),mode,plan,cleanup)
        if sha(binary.read_bytes())!=plan['pe_sha256']:raise ValueError('original PE changed during observation')
        record=dict(label=label,summary=rows[-1],observer_stdout_sha256=sha((d/'observer.stdout').read_bytes()),
            child_stdout_sha256=sha((d/'child.stdout').read_bytes()),child_stderr_sha256=sha((d/'child.stderr').read_bytes()))
        if not cleanup:
            expected=bytes.fromhex(plan['original_stdout_hex']) if label=='baseline' else b''
            if (d/'child.stdout').read_bytes()!=expected or (d/'child.stderr').read_bytes():raise ValueError('instrumented physical output differs: '+label)
            record['observed']=summarize(rows,label,plan);record['modules']=modules(rows)
        results.append(record)
        (d/'analysis.json').write_text(json.dumps(record,indent=2)+'\n')
    report=dict(plan,kind='separately instrumented original CRT observations; no whole-PE translations',platform=platform.platform(),
        observer_source_sha256=sha(source.read_bytes()),observer_sha256=sha(observer.read_bytes()),build_command=command,
        vc_tools_version=os.environ.get('VCToolsVersion'),runs=results,
        counts=dict(ordinary_baselines_inherited=1,unmodified_instrumented_api_case=1,scripted_api_success_cases=3,scripted_handle_real_os_failure_cases=1,cleanup_failure_controls=1),
        limits_of_claim=['PTD errno/doserrno values remain static instruction-derived predictions; this observer does not read those runtime fields.',
            'All five original runs use the same unmodified PE and fixed payload, not arbitrary CRT inputs.',
            'INT3/TF and scripted API outputs perturb the owned child and are never ordinary Windows baselines.',
            'Positive-short and zero-success results skip WriteFile: no physical bytes are written by those scripted calls.',
            'The invalid-handle argument is scripted, but WriteFile itself executes and supplies its actual failure result.',
            'Thread creation is logged, not suppressed. Any observed site on another thread rejects; arbitrary concurrent FILE mutation remains outside evidence.',
            'Module versions and loaded API addresses are observed; no general CRT ABI or full startup/termination equivalence follows.'])
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(pe_sha256=plan['pe_sha256'],runs=len(results),whole_pe_translation_pairs=0)))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('original',type=Path);parser.add_argument('output',type=Path)
    parser.add_argument('--prepare-only',action='store_true');args=parser.parse_args()
    if args.prepare_only:
        args.output.mkdir(parents=True,exist_ok=False);print(json.dumps(prepare(args.original.resolve(),args.output.resolve()),indent=2))
    else:run(args.original.resolve(),args.output.resolve())
