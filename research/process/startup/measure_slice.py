"""Original Windows handler bytes and actual exception/restoration observation."""
from pathlib import Path
import hashlib,json,struct,subprocess,sys
from inventory import mapped_bytes
here=Path(__file__).resolve().parent
sys.path.insert(0,str(here.parents[2]/'corpus'))
from launch import execute
out=Path(sys.argv[1]).resolve();out.mkdir(parents=True,exist_ok=False)
source=here/'slice_probe.c'
frozen=json.loads((here/'slice-frozen.json').read_text())
if hashlib.sha256(source.read_bytes()).hexdigest()!=frozen['source_sha256']:raise ValueError('source changed')
exe=out/'slice.exe'
cmd=['cl','/nologo','/W4','/O2','/GS',str(source),'/Fe'+str(exe),'/Fo'+str(out/'slice.obj'),'/link','/SAFESEH:NO']
b=subprocess.run(cmd,capture_output=True,timeout=60);(out/'build.txt').write_bytes(b.stdout+b.stderr)
if b.returncode:raise RuntimeError('build failed')
data=exe.read_bytes();digest=hashlib.sha256(data).hexdigest()
p=execute([str(exe)],out/'stdout',out/'stderr',out/'launch',{'pe_sha256':digest},frozen,timeout=10)
if p.returncode or (out/'stderr').read_bytes():raise ValueError('Windows outcome')
r=json.loads((out/'stdout').read_text())
expected=[42,11,12,13,32768,33024,16,17,r['fault_rva']+2,514]
if r['actual_result']!=42 or r['disposition']!=0 or r['context']!=expected:raise ValueError('independent expected state')
pe=struct.unpack_from('<I',data,60)[0];base=struct.unpack_from('<I',data,pe+52)[0]
if mapped_bytes(data,base+r['fault_rva'],2)!=b'\x0f\x0b':raise ValueError('fault instruction')
code=mapped_bytes(data,base+r['handler_rva'],24)
(out/'handler.bin').write_bytes(code)
r.update(source_sha256=frozen['source_sha256'],pe_sha256=digest,handler_sha256=hashlib.sha256(code).hexdigest(),command=cmd,kind='Windows original handler and restored exception; not translated PE')
if hashlib.sha256(exe.read_bytes()).hexdigest()!=digest:raise ValueError('artifact changed')
(out/'report.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
