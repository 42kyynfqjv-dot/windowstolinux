"""One-time preregistration; do not rerun to accommodate converter failures."""
import hashlib,json
from pathlib import Path
p=Path(__file__).parent
inputs=[b'',b'Hello, world!\r\n',bytes(range(256))]+[bytes((i*37+97)%256 for i in range(n)) for n in [1,255,256,257,511,512,513,4097]]
# Independent byte lookup specification, including NUL and all non-ASCII bytes.
table=bytes(range(97))+b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'+bytes(range(123,256))
v=[dict(name=f'case{i}',input_hex=b.hex(),stdout_hex=b.translate(table).hex(),stderr_hex='',exit=0) for i,b in enumerate(inputs)]
(p/'cases.json').write_text(json.dumps(v,indent=2)+'\n')
m=dict(configurations={'O1':['/O1'],'O2':['/O2']},compile_flags=['/nologo','/Bv','/W4','/GS-','/Zl','/c'],link_flags=['/nologo','/machine:x86','/subsystem:console','/nodefaultlib','/entry:entry@0'],libraries=['kernel32.lib'],sha256={n:hashlib.sha256((p/n).read_bytes()).hexdigest() for n in ['filter.c','cases.json']})
(p/'frozen.json').write_text(json.dumps(m,indent=2)+'\n')
