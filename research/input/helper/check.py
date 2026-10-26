"""Bind trusted compiler artifact evidence; not a production PE parser."""
import hashlib,json,struct,sys
from pathlib import Path
root=Path(sys.argv[1]);report=json.loads((root/'input-diversity.json').read_text(encoding='utf-8'))
i=next(x for x in report['programs'] if x['name']=='helper');data=(root/'div_helper.exe').read_bytes()
assert hashlib.sha256(data).hexdigest()==i['pe_sha256']
assert i['accepted'] and i['converter_error']=='' and len(i['observations'])==17
pe=struct.unpack_from('<I',data,60)[0];table=pe+24+struct.unpack_from('<H',data,pe+20)[0];raw=struct.unpack_from('<I',data,table+20)[0]
assert struct.unpack_from('<I',data,pe+40)[0]==0x1040
assert data[raw+0x3b:raw+0x40]==b'\xcc'*5
for off,hexbytes in [(0,'8b542404'),(4,'0fb70a'),(0x13,'837c240802'),(0x1a,'0fb75202'),(0x7d,'50'),(0x7e,'8d442404'),(0x83,'e878ffffff'),(0x88,'83c408'),(0x8b,'83c408')]:
 b=bytes.fromhex(hexbytes);assert data[raw+off:raw+off+len(b)]==b
print('HELPER CONTRACT: same PE',i['pe_sha256'],'entry1040/call1000/nine forms/five padding bytes; production accepted; actual native comparisons checked separately')
