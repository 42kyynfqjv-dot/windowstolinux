"""Bind original Windows scope/helper bytes to composed native slice observation."""
from pathlib import Path
import hashlib,json,struct,subprocess,sys
from inventory import mapped_bytes
here=Path(__file__).resolve().parent
sys.path.insert(0,str(here.parents[2]/'corpus'))
from launch import execute
root=Path(sys.argv[1]).resolve();compiler=Path(sys.argv[2]).resolve()
r=json.loads((root/'report.json').read_text());pe=(root/'unwind.exe').read_bytes()
sha=lambda b:hashlib.sha256(b).hexdigest()
if sha(pe)!=r['pe_sha256']:raise ValueError('retained PE changed')
base=r['image_base'];header=struct.unpack_from('<I',pe,60)[0]
if struct.unpack_from('<I',pe,header+52)[0]!=base:raise ValueError('preferred base changed')
table=mapped_bytes(pe,base+r['table_rva'],r['scope_table_size'])
if sha(table)!=r['scope_table_sha256'] or table!=(root/'scope-table.bin').read_bytes():raise ValueError('original scope binding')
(root/'scope.bin').write_bytes(table)
lines=[]
for block in r['cleanups']+[r['restore']]:
 code=mapped_bytes(pe,base+block['rva'],block['size'])
 if sha(code)!=block['sha256'] or code!=(root/block['file']).read_bytes():raise ValueError('original code binding')
 if block in r['cleanups']:lines.append(str(block['rva'])+' '+block['file'])
 else:(root/'restore.bin').write_bytes(code)
(root/'cleanup.list').write_text('\n'.join(lines)+'\n')
(root/'active.txt').write_text('-1 2 0\n')
target=r['restore_target_rva'];target_code=mapped_bytes(pe,base+target,15)
if target_code[:1].hex()!=r['restore_target_first_byte']:raise ValueError('target binding')
(root/'target.bin').write_bytes(target_code)
def run(cmd,label,timeout):
 try:p=subprocess.run(cmd,capture_output=True,timeout=timeout)
 except subprocess.TimeoutExpired as e:
  (root/(label+'.stdout')).write_bytes(e.stdout or b'');(root/(label+'.stderr')).write_bytes(e.stderr or b'');raise
 (root/(label+'.stdout')).write_bytes(p.stdout);(root/(label+'.stderr')).write_bytes(p.stderr)
 if p.returncode:raise RuntimeError(label+': '+p.stderr.decode(errors='replace'))
source=root/'unwind.rs'
run([str(compiler),str(root),str(base),str(r['table_rva']),str(r['restore']['rva']),str(target),str(source)],'conversion',20)
obs=r['observation']; saved=[obs['restore_eax'],11,12,13,32768,33024,16,17,target,514]
current=[1,2,3,40,4096,8192,60,70,123,514]
expected=[obs['restore_eax'],None,None,40,32768,33024,60,70,target,None]
rust_array=lambda a:'['+','.join('None' if v is None else 'Some('+str(v)+')' for v in a)+']'
harness='\nfn main(){let saved='+repr(saved)+';let current='+repr(current)+';let o=unwind(&[300,200,100],saved,current,0).unwrap();assert_eq!(o.trace,'+str(obs['trace'])+');assert_eq!(o.locals,vec![Some('+str(obs['selected'])+'),Some('+str(obs['outer'])+'),Some('+str(obs['inner'])+')]);assert_eq!(o.live,vec![true,false,false]);assert_eq!(o.restored,'+rust_array(expected)+');}\n'
(root/'native.rs').write_text(source.read_text()+harness)
run(['rustc','--edition=2021',str(root/'native.rs'),'-o',str(root/'native')],'rustc',60)
p=execute([str(root/'native')],root/'native.stdout',root/'native.stderr',root/'native-launch',{'pe_sha256':r['pe_sha256']},{'exit':0},timeout=10)
if p.returncode:raise ValueError('native comparison failed')
report=dict(kind='composed original cleanup helpers and separate manual restore slice; zero whole-PE pairs',pe_sha256=r['pe_sha256'],scope_sha256=r['scope_table_sha256'],restore_sha256=r['restore']['sha256'],rust_sha256=sha(source.read_bytes()),trace=obs['trace'],locals=[obs['selected'],obs['outer'],obs['inner']],restored=expected,limits=r['limits'])
(root/'native-report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
