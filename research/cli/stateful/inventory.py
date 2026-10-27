"""Evidence-only instruction/PE inventory; never an execution eligibility parser."""
import json,re,struct,hashlib,sys,collections
from pathlib import Path
root=Path(sys.argv[1]);r=json.loads((root/'report.json').read_text());rows=[]
for row in r['programs']:
 stem=row['name']+'_'+row['config'];b=(root/(stem+'.exe')).read_bytes();assert hashlib.sha256(b).hexdigest()==row['pe_sha256']
 u16=lambda p:struct.unpack_from('<H',b,p)[0]
 u32=lambda p:struct.unpack_from('<I',b,p)[0]
 pe=u32(60);op=pe+24;table=op+u16(pe+20);base=u32(op+28);sections=[]
 for n in range(u16(pe+6)):
  at=table+40*n;sections.append(dict(name=b[at:at+8].split(b'\0')[0].decode(),virtual_size=u32(at+8),rva=u32(at+12),raw_size=u32(at+16),raw_offset=u32(at+20),permissions=hex(u32(at+36))))
 instructions=[]
 for line in (root/(stem+'-disasm.txt')).read_text(errors='replace').splitlines():
  m=re.match(r'\s*([0-9A-F]{8}):\s+((?:[0-9A-F]{2}\s+)+)\s*(\w+)\s*(.*)',line)
  if m:instructions.append(dict(rva=hex(int(m[1],16)-base),bytes=m[2].split(),mnemonic=m[3],operands=m[4]))
 rows.append(dict(name=row['name'],config=row['config'],pe_sha256=row['pe_sha256'],entry_rva=hex(u32(op+16)),preferred_base=hex(base),sections=sections,mnemonics=dict(sorted(collections.Counter(x['mnemonic'] for x in instructions).items())),instructions=instructions,conversion=row['conversion']))
(root/'inventory.json').write_text(json.dumps(rows,indent=2)+'\n')
