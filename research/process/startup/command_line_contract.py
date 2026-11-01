"""Frozen command-line expectations and independent Windows probe decoding."""
import json
from pathlib import Path
import struct
HERE=Path(__file__).resolve().parent

def vectors():
    data=json.loads((HERE/'command-line-vectors.json').read_text(encoding='utf-8'))
    if data['version']!=1 or data['codepage']!=65001:raise ValueError('unsupported frozen command-line profile')
    for row in data['cases']:
        if row['raw'].encode('utf-8').hex()!=row['utf8_hex'] or row['raw'].encode('utf-16le').hex()!=row['utf16le_hex']:raise ValueError('inconsistent frozen encoding expectations')
    return data['cases']

def rust_vectors():
    quote=lambda s:json.dumps(s,ensure_ascii=False)
    rows=[]
    for row in vectors():
        args='vec!['+','.join(quote(x)+'.to_owned()' for x in row['argv'])+']'
        a=list(bytes.fromhex(row['utf8_hex'])+b'\0');w=list(bytes.fromhex(row['utf16le_hex'])+b'\0\0')
        rows.append('('+args+',vec!'+str(a)+',vec!'+str(w)+')')
    return 'fn command_line_vectors()->Vec<(Vec<String>,Vec<u8>,Vec<u8>)>{vec!['+','.join(rows)+']}\n'

def decode_probe(blob):
    cursor=0
    def word():
        nonlocal cursor
        if cursor+4>len(blob):raise ValueError('truncated command-line probe word')
        n=struct.unpack_from('<I',blob,cursor)[0];cursor+=4;return n
    def buffer():
        nonlocal cursor
        n=word()
        if n>262144 or cursor+n>len(blob):raise ValueError('truncated/oversize command-line probe buffer')
        b=blob[cursor:cursor+n];cursor+=n;return b
    if word()!=0x31444d43:raise ValueError('command-line probe version')
    acp=word();stable=word();a=buffer();w=buffer();count=word()
    if count>32767:raise ValueError('command-line probe argc bound')
    argv=[buffer() for _ in range(count)]
    if cursor!=len(blob):raise ValueError('extra command-line probe bytes')
    return dict(acp=acp,stable=stable,a=a,w=w,argv=argv)

def validate_probe(blob, row):
    d=decode_probe(blob)
    if d['acp']!=65001 or d['stable']!=3:raise ValueError('unobserved ACP or unstable API pointer')
    if d['a']!=bytes.fromhex(row['utf8_hex'])+b'\0' or d['w']!=bytes.fromhex(row['utf16le_hex'])+b'\0\0':raise ValueError('original GetCommandLineA/W differs from frozen raw string')
    if d['argv']!=[x.encode('utf-16le')+b'\0\0' for x in row['argv']]:raise ValueError('original MSVC argv differs from frozen inputs')
    return d

if __name__=='__main__':(HERE/'command-line-vectors.rs').write_text(rust_vectors(),encoding='utf-8')
