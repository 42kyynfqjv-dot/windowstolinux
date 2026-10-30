"""Compile unchanged Windows handler slice to Rust/ELF; compare integer state."""
from pathlib import Path
import hashlib,json,struct,subprocess,sys
from inventory import mapped_bytes
here=Path(__file__).resolve().parent
sys.path.insert(0,str(here.parents[2]/'corpus'))
from launch import execute
root=Path(sys.argv[1]).resolve();compiler=Path(sys.argv[2]).resolve()
r=json.loads((root/'report.json').read_text());code=root/'handler.bin'
pe=(root/'slice.exe').read_bytes()
if hashlib.sha256(pe).hexdigest()!=r['pe_sha256']:raise ValueError('PE changed')
at=struct.unpack_from('<I',pe,60)[0];base=struct.unpack_from('<I',pe,at+52)[0]
if mapped_bytes(pe,base+r['handler_rva'],24)!=code.read_bytes():raise ValueError('slice not from retained PE')
if hashlib.sha256(code.read_bytes()).hexdigest()!=r['handler_sha256']:raise ValueError('slice changed')
def run(command,label,timeout):
    try:
        p=subprocess.run(command,capture_output=True,timeout=timeout)
    except subprocess.TimeoutExpired as e:
        (root/(label+'.stdout')).write_bytes(e.stdout or b'')
        (root/(label+'.stderr')).write_bytes(e.stderr or b'')
        raise
    (root/(label+'.stdout')).write_bytes(p.stdout);(root/(label+'.stderr')).write_bytes(p.stderr)
    if p.returncode:raise RuntimeError(label+' failed: '+p.stderr.decode(errors='replace'))
generated=root/'handler.rs'
run([str(compiler),str(code),str(r['handler_rva']),str(r['fault_rva']),str(r['resume_rva']),str(generated)],'conversion',20)
source=generated.read_text()
initial=[10,11,12,13,32768,33024,16,17,r['fault_rva'],514]
source+='\nfn main(){let mut c='+repr(initial)+';let mut invalid=c;invalid[8]^=1;let before=invalid;assert!(handler(&mut invalid).is_err());assert_eq!(invalid,before);assert_eq!(handler(&mut c),Ok(0));assert_eq!(c,'+repr(r['context'])+');}\n'
(root/'native.rs').write_text(source)
run(['rustc','--edition=2021',str(root/'native.rs'),'-o',str(root/'native')],'rustc',60)
p=execute([str(root/'native')],root/'native.stdout',root/'native.stderr',root/'native-launch',{'handler_sha256':r['handler_sha256']},{'exit':0},timeout=10)
if p.returncode:raise ValueError('native assertions failed')
print(json.dumps(dict(kind='unchanged handler slice native comparison; zero whole-PE translations',pe_sha256=r['pe_sha256'],handler_sha256=r['handler_sha256'],rust_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),context=r['context'])))
