"""Test-only inventory of authored compiler artifacts; never authorizes emission.
Dumpbin text is evidence, not a complete control-flow or effect analysis.
"""
import hashlib,json,re,struct,sys
from pathlib import Path

def inventory(root):
    records=json.loads((root/'heldout-x86.json').read_text())
    result=[]
    for name in ('held_crt','held_args','held_file'):
        r=next(x for x in records if x['kind']==name)
        b=(root/(name+'.exe')).read_bytes()
        assert hashlib.sha256(b).hexdigest()==r['sha256']
        assert hashlib.sha256(Path(r['source']).read_bytes()).hexdigest()==r['source_sha256']
        assert not r['conversion_accepted']
        def u(at):return struct.unpack_from('<I',b,at)[0]
        pe=u(60);o=pe+24;table=o+struct.unpack_from('<H',b,pe+20)[0]
        assert b[pe:pe+4]==b'PE\0\0' and struct.unpack_from('<H',b,o)[0]==0x10b
        sections=[struct.unpack_from('<IIII',b,table+40*i+8) for i in range(struct.unpack_from('<H',b,pe+6)[0])]
        def raw(rva,n):
            matches=[p+rva-v for vs,v,s,p in sections if v<=rva and rva+n<=v+min(vs,s)]
            assert n>0 and len(matches)==1 and matches[0]+n<=len(b)
            return matches[0]
        base=u(o+28);entry=u(o+16);at=raw(entry,10)
        # Independently check the actual entry's CALL then JMP bytes, not guessed main.
        assert b[at]==0xe8 and b[at+5]==0xe9
        targets=[entry+5+struct.unpack_from('<i',b,at+1)[0],entry+10+struct.unpack_from('<i',b,at+6)[0]]
        for t in targets:raw(t,1)
        dirs={str(i):[u(o+96+8*i),u(o+100+8*i)] for i in range(16) if u(o+100+8*i)}
        lc=raw(dirs['10'][0],64);cookie=u(lc+60);raw(cookie-base,4)
        header=(root/(name+'-headers.txt')).read_text()
        imports={};dll=None
        for line in header.splitlines():
            m=re.fullmatch(r'\s+([\w.-]+\.dll)\s*',line,re.I)
            if m:dll=m[1];imports[dll]=[]
            m=re.fullmatch(r'\s+[0-9A-F]+ ([\w?@$]+)\s*',line)
            if m and dll:imports[dll].append(m[1])
        dis=(root/(name+'-disassembly.txt')).read_text()
        # These occurrences are whole disassembly observations, NOT reachable counts.
        indirect=[x.strip().split(':')[0] for x in dis.splitlines() if re.search(r'\b(call|jmp)\s+(?:dword|eax|ebx|ecx|edx|esi|edi)',x)]
        version=(root/(name+'-compile.txt')).read_text()
        result.append(dict(kind=name,pe_sha256=r['sha256'],source_sha256=r['source_sha256'],freeze_commit=r['freeze_commit'],
            compile_flags=r['compile_flags'],link_flags=r['link_flags'],compiler_versions=sorted(set(re.findall(r'Version ([0-9.]+)',version))),
            baseline=json.loads((root/(name+'-baseline.json')).read_text()),entry_rva=entry,entry_call_rva=targets[0],entry_jump_rva=targets[1],
            directories=dirs,security_cookie_va=cookie,imports=imports,whole_disassembly_indirect_transfers=indirect,
            complete_reachable_graph=False,emission_allowed=False))
    return result
if __name__=='__main__':
    root=Path(sys.argv[1]); report=inventory(root)
    if len(sys.argv)>2:
        assert report==json.loads((root/'crt-inventory.json').read_text())
    else:
        (root/'crt-inventory.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
