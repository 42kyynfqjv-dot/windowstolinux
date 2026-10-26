"""Read trusted compiler evidence; never grants production admission."""
import collections,hashlib,json,re,struct,sys
from pathlib import Path
root=Path(sys.argv[1]);report=json.loads((root/'report.json').read_text())
def u16(b,o):return struct.unpack_from('<H',b,o)[0]
def u32(b,o):return struct.unpack_from('<I',b,o)[0]
result=[]
for row in report['programs']:
 stem='uppercase_'+row['config'];b=(root/(stem+'.exe')).read_bytes();assert hashlib.sha256(b).hexdigest()==row['pe_sha256']
 pe=u32(b,60);opt=pe+24;table=opt+u16(b,pe+20);sections=[]
 for i in range(u16(b,pe+6)):
  at=table+i*40;sections.append(dict(name=b[at:at+8].rstrip(b'\0').decode('ascii'),virtual_size=u32(b,at+8),rva=u32(b,at+12),raw_size=u32(b,at+16),raw_offset=u32(b,at+20),flags=hex(u32(b,at+36))))
 lines=(root/(stem+'-disasm.txt')).read_text();instructions=[]
 for line in lines.splitlines():
  m=re.match(r'\s*([0-9A-Fa-f]{8}):\s+((?:[0-9A-Fa-f]{2}\s+)+)([a-z][a-z0-9]*)\s*(.*)',line)
  if m:instructions.append(dict(va=m[1],bytes=''.join(m[2].split()),mnemonic=m[3],operands=m[4]))
 assert instructions
 result.append(dict(config=row['config'],pe_sha256=row['pe_sha256'],entry_rva=hex(u32(b,opt+16)),image_base=hex(u32(b,opt+28)),sections=sections,directories=[dict(index=i,rva=u32(b,opt+96+i*8),size=u32(b,opt+100+i*8)) for i in range(16) if u32(b,opt+96+i*8) or u32(b,opt+100+i*8)],instruction_lines=instructions,mnemonics=dict(sorted(collections.Counter(i['mnemonic'] for i in instructions).items())),imports_text=(root/(stem+'-imports.txt')).read_text(),conversion=row['conversion']))
(root/'inventory.json').write_text(json.dumps(result,indent=2)+'\n')
for r in result:print(r['config'],r['mnemonics'],r['conversion'])
print('Listing inventory includes padding; full dumpbin listings retain wrapped byte continuations. Not a reachable-CFG proof.')
