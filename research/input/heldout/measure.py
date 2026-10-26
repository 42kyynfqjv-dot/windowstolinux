"""Frozen measurement, not a converter acceptance policy or fixture generator."""
import argparse,hashlib,json,os,platform,subprocess
from pathlib import Path
ap=argparse.ArgumentParser();ap.add_argument('evidence',type=Path);ap.add_argument('--compare',action='store_true');args=ap.parse_args()
root=args.evidence.resolve();src=Path(__file__).resolve().parent;repo=src.parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p,x):p.write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def run(cmd,**kw):return subprocess.run(cmd,capture_output=True,timeout=30,**kw)
m=json.loads((src/'frozen.json').read_text(encoding='utf-8'))
for name,h in m['sha256'].items():assert sha(src/name)==h,('frozen bytes changed',name)
cases=json.loads((src/'cases.json').read_text(encoding='utf-8'))
win=root/'held-input.json';outpath=root/('held-input-native.json' if args.compare else 'held-input.json')
old=json.loads(win.read_text(encoding='utf-8')) if args.compare else None
if old:assert old['manifest']==m
out=dict(manifest=m,platform=platform.platform(),programs=[])
for case in cases:
 for config,flags in m['configurations'].items():
  key=case['name']+'_'+config;stem='div_hold_'+key;pe=root/(stem+'.exe');rs=root/(stem+('-native.rs' if args.compare else '.rs'))
  item=dict(name=case['name'],config=config,observations=[]);out['programs'].append(item)
  if not args.compare:
   commands=[('compile',['cl']+m['compile_flags']+flags+[str(src/(case['name']+'.c')),'/Fo'+stem+'.obj']),('link',['link']+m['link_flags']+[stem+'.obj']+m['libraries']+['/out:'+stem+'.exe']),('disassembly',['dumpbin','/disasm',str(pe)]),('imports',['dumpbin','/imports',str(pe)])]
   for stage,cmd in commands:
    p=run(cmd,cwd=root);(root/(stem+'-'+stage+'.txt')).write_bytes(p.stdout+p.stderr);assert p.returncode==0,(key,stage,p.stderr)
   item.update(source_sha256=sha(src/(case['name']+'.c')),commands=commands)
  else:
   prior=next(x for x in old['programs'] if x['name']==case['name'] and x['config']==config)
   assert sha(pe)==prior['pe_sha256'] and sha(src/(case['name']+'.c'))==prior['source_sha256']
  item['pe_sha256']=sha(pe);rs.write_text('preserve',encoding='utf-8')
  converter=repo/'target/debug'/('w2l' if args.compare else 'w2l.exe')
  p=run([str(converter),str(pe),str(rs)]);assert p.returncode in (0,1),(key,p.returncode,p.stderr)
  item.update(accepted=p.returncode==0,converter_error=p.stderr.decode('utf-8'))
  if args.compare:assert item['accepted']==prior['accepted'] and item['converter_error']==prior['converter_error']
  if item['accepted']:
   item['generated_sha256']=sha(rs)
   if args.compare:
    assert item['generated_sha256']==prior['generated_sha256']==sha(root/(stem+'.rs'))
    q=run([str(converter),str(pe),str(rs)],env=dict(os.environ,W2L_INPUT='unobserved-converter-input'));assert q.returncode==0 and sha(rs)==item['generated_sha256']
    executable=root/(stem+'-native');q=run(['rustc','--edition=2021',str(rs),'-o',str(executable)]);assert q.returncode==0,q.stderr
    item['elf_sha256']=sha(executable)
  else:assert rs.read_text(encoding='utf-8')=='preserve'
  if not args.compare or item['accepted']:
   executable=executable if args.compare else pe
   for index,v in enumerate(case['vectors']):
    env={} if args.compare else {k:x for k,x in os.environ.items() if k.upper() in ('SYSTEMROOT','WINDIR','TEMP','TMP','PATH','COMSPEC')}
    if v['value'] is not None:env['W2L_INPUT']=v['value']
    write(root/(stem+'-stage.json'),dict(stage='launch',index=index,command=[str(executable)],pe_sha256=sha(pe),platform=platform.platform()))
    try:p=run([str(executable)],env=env)
    except subprocess.TimeoutExpired as e:
     write(root/(stem+'-timeout.json'),dict(index=index,timeout=30,stdout_hex=(e.stdout or b'').hex(),stderr_hex=(e.stderr or b'').hex(),pe_sha256=sha(pe)));raise
    observation=dict(index=index,exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex());item['observations'].append(observation);write(outpath,out)
    assert observation==dict(index=index,exit=v['exit'],stdout_hex=v['stdout_hex'],stderr_hex=v['stderr_hex']),(key,v,observation)
   if args.compare:assert item['observations']==prior['observations']
  assert sha(pe)==item['pe_sha256'];write(outpath,out)
  print(key,'ACCEPTED' if item['accepted'] else item['converter_error'].strip())
print('HELD INPUT:',len(out['programs']),'artifacts;',sum(len(x['observations']) for x in out['programs']),'observations; accepted',sum(x['accepted'] for x in out['programs']))
