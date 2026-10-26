"""Bind design evidence to unchanged compiler output; never grants admission."""
import hashlib,json,struct,sys
from pathlib import Path
root=Path(sys.argv[1]);report=json.loads((root/'input-diversity.json').read_text(encoding='utf-8'))
item=next(x for x in report['programs'] if x['name']=='squares')
p=root/'div_squares.exe';data=p.read_bytes();assert hashlib.sha256(data).hexdigest()==item['pe_sha256']
assert item['accepted'] is True and item['converter_error']==''
assert len(item['observations'])==17
# Literal instruction bytes independently inventoried from MSVC disassembly.
pe=struct.unpack_from('<I',data,60)[0];table=pe+24+struct.unpack_from('<H',data,pe+20)[0]
raw=struct.unpack_from('<I',data,table+20)[0];size=struct.unpack_from('<I',data,table+8)[0]
assert size==128
for offset,expected in [(0x4e,'83c2d0'),(0x51,'0fafd2'),(0x59,'8b4c2402'),(0x66,'0fb7c9'),(0x69,'83c1d0'),(0x6c,'0fafc9'),(0x6f,'03d1')]:
 b=bytes.fromhex(expected);assert data[raw+offset:raw+offset+len(b)]==b
print('NONLINEAR INVENTORY: seven missing forms bound to unchanged PE',item['pe_sha256'],'; production accepted; actual native evidence checked separately')
