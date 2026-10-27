"""Compile unchanged Windows handler slice to Rust/ELF; compare full integer state."""
from pathlib import Path
import hashlib,json,subprocess,sys
root=Path(sys.argv[1]).resolve();compiler=Path(sys.argv[2]).resolve()
r=json.loads((root/'report.json').read_text());code=root/'handler.bin'
if hashlib.sha256(code.read_bytes()).hexdigest()!=r['handler_sha256']:raise ValueError('slice changed')
generated=root/'handler.rs'
subprocess.run([str(compiler),str(code),str(r['handler_rva']),str(r['fault_rva']),str(r['resume_rva']),str(generated)],check=True)
source=generated.read_text()
initial=[10,11,12,13,32768,33024,16,17,r['fault_rva'],514]
source+='\nfn main(){let mut c='+repr(initial)+'u32_PLACEHOLDER;assert_eq!(handler(&mut c),0);assert_eq!(c,'+repr(r['context'])+');}\n'
source=source.replace('u32_PLACEHOLDER','')
(root/'native.rs').write_text(source)
subprocess.run(['rustc','--edition=2021',str(root/'native.rs'),'-o',str(root/'native')],check=True)
subprocess.run([str(root/'native')],check=True)
print(json.dumps(dict(kind='unchanged handler slice native comparison; zero whole-PE translations',pe_sha256=r['pe_sha256'],handler_sha256=r['handler_sha256'],rust_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),context=r['context'])))
