"""Frozen held-out input compositions: no production support changes permitted."""
import argparse,hashlib,json,os,platform,subprocess,struct
from pathlib import Path
ap=argparse.ArgumentParser();ap.add_argument('evidence',type=Path);ap.add_argument('--compare',action='store_true');a=ap.parse_args()
root=a.evidence.resolve();repo=Path(__file__).resolve().parents[3];src=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
manifest=json.loads((src/'frozen.json').read_text(encoding='utf-8'))
for n,h in manifest['sha256'].items():assert sha(src/n)==h,('frozen source changed',n)
cases=json.loads((src/'cases.json').read_text(encoding='utf-8'))
report=root/'input-diversity.json';native_report=root/'input-diversity-native.json'
def write(path,obj):path.write_text(json.dumps(obj,indent=2)+'\n',encoding='utf-8')
def run(args,**kw):return subprocess.run(args,capture_output=True,timeout=30,**kw)
if a.compare:
    prior=json.loads(report.read_text(encoding='utf-8'));assert prior['manifest']==manifest
    out=dict(manifest=manifest,programs=[])
else:out=dict(manifest=manifest,platform=platform.platform(),programs=[])
for case in cases:
    name=case['name'];stem='div_'+name;pe=root/(stem+'.exe');rs=root/(stem+'.rs')
    item=dict(name=name,observations=[]);out['programs'].append(item)
    if not a.compare:
        commands=[('compile',['cl']+manifest['compile_flags']+[str(src/(name+'.c')),'/Fo'+stem+'.obj']),
                  ('link',['link']+manifest['link_flags']+[stem+'.obj']+manifest['libraries']+['/out:'+stem+'.exe']),
                  ('disassembly',['dumpbin','/disasm',str(pe)]),('imports',['dumpbin','/imports',str(pe)])]
        for stage,command in commands:
            p=run(command,cwd=root);(root/(stem+'-'+stage+'.txt')).write_bytes(p.stdout+p.stderr)
            assert p.returncode==0,(stage,p.stderr)
        item.update(pe_sha256=sha(pe),source_sha256=sha(src/(name+'.c')),compile_command=commands[0][1],link_command=commands[1][1])
        executable=pe
    else:
        old=next(x for x in prior['programs'] if x['name']==name)
        assert sha(pe)==old['pe_sha256'] and sha(src/(name+'.c'))==old['source_sha256']
        item['pe_sha256']=sha(pe)
    converter=repo/'target/debug'/('w2l.exe' if not a.compare else 'w2l')
    output=root/(stem+'-linux.rs') if a.compare else rs
    output.write_text('preserve',encoding='utf-8')
    p=run([str(converter),str(pe),str(output)])
    assert p.returncode in (0,1),(name,p.returncode,p.stderr)
    item.update(accepted=p.returncode==0,converter_error=p.stderr.decode('utf-8'))
    assert item['accepted']==(name in ('guard_join','squares')),('SUB557 acceptance gate',name,item)
    if item['accepted']:
        item['generated_sha256']=sha(output)
        if a.compare:
            assert old['accepted'] and item['generated_sha256']==old['generated_sha256']==sha(rs)
            env=dict(os.environ,W2L_INPUT='different-converter-environment')
            q=run([str(converter),str(pe),str(output)],env=env)
            assert q.returncode==0 and sha(output)==item['generated_sha256']
            executable=root/(stem+'-native')
            q=run(['rustc','--edition=2021',str(output),'-o',str(executable)]);assert q.returncode==0,q.stderr
    else:
        assert output.read_text(encoding='utf-8')=='preserve'
        if a.compare:
            assert old['accepted'] is False and item['converter_error']==old['converter_error']
    if not a.compare or item['accepted']:
        for v in case['vectors']:
            env={k:value for k,value in os.environ.items() if k.upper() in ('SYSTEMROOT','WINDIR','TEMP','TMP','PATH','COMSPEC')} if not a.compare else {}
            if v['value'] is not None:env['W2L_INPUT']=v['value']
            # Persist exact command/hash/input case before execution; no retries.
            write(root/(stem+'-stage.json'),dict(stage='launch',name=v['name'],command=[str(executable)],pe_sha256=sha(pe),platform=platform.platform()))
            try:p=run([str(executable)],env=env)
            except subprocess.TimeoutExpired as e:
                write(root/(stem+'-timeout.json'),dict(name=v['name'],timeout=30,stdout_hex=(e.stdout or b'').hex(),stderr_hex=(e.stderr or b'').hex(),pe_sha256=sha(pe)))
                raise
            actual=dict(name=v['name'],exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex())
            item['observations'].append(actual)
            write(native_report if a.compare else report,out)
            assert actual==dict(name=v['name'],exit=v['exit'],stdout_hex='',stderr_hex=''),actual
        if a.compare:assert item['observations']==old['observations']
    if a.compare and name in ('guard_join','squares'):
        item['elf_sha256']=sha(executable)
        extra=[f'{i:02d}' for i in range(100)]+['/',':','９','😀','\x01']
        for value in extra:
            expected=(sum(int(c)**2 for c in value) if name=='squares' else int(value)) if all('0'<=c<='9' for c in value) else 202
            p=run([str(executable)],env={'W2L_INPUT':value})
            assert (p.returncode,p.stdout,p.stderr)==(expected,b'',b'')
        item['additional_native_cases']=len(extra)
        blob=pe.read_bytes();ph=struct.unpack_from('<I',blob,60)[0];table=ph+24+struct.unpack_from('<H',blob,ph+20)[0]
        raw=struct.unpack_from('<I',blob,table+20)[0]
        bad=root/'guard-negative.exe';sink=root/'guard-negative.rs';rejected=0
        # Separate mutated files only. Frozen original PE never changed.
        mutations=([(7,2),(0x32,0x76),(0x40,0x76),(0x45,4),(0x4d,0x76),(0x59,0x76),(0x49,0x67),(0x71,0x14),(0x89,1)] if name=='guard_join' else [(7,2),(0x18,0x76),(0x34,0x77),(0x49,0x76),(0x5c,4),(0x64,0x76),(0x52,0xae),(0x6d,0xae),(0x70,0xd9)])
        for offset,value in mutations:
            b=bytearray(blob);b[raw+offset]=value;bad.write_bytes(b);sink.write_text('preserve')
            p=run([str(converter),str(bad),str(sink)])
            assert p.returncode==1 and sink.read_text()=='preserve',(offset,p.stderr)
            rejected+=1
        item['unsafe_cli_rejections']=rejected
    assert sha(pe)==item['pe_sha256']
    write(native_report if a.compare else report,out)
    print(name,'ACCEPTED' if item['accepted'] else 'REJECTED: '+item['converter_error'].strip())
print('DIVERSITY:3 frozen programs;51 Windows scenarios; guard_join+squares34 translated pairs; helper rejected')
