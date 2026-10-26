"""Execute independent corpus through real converter and original Windows."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from generate import build, VERSION, SEED

windows='--windows' in sys.argv
manifest=json.loads(Path(__file__).with_name('expected.json').read_text())
assert (manifest['version'],manifest['seed'])==(VERSION,SEED)
assert [c['id'] for c in manifest['cases']] == list(range(32))
converter=Path('target/debug/w2l').resolve()
digest=hashlib.sha256()
with tempfile.TemporaryDirectory() as directory:
    root=Path(directory);exe=root/'case.exe';rs=root/'case.rs';elf=root/'case'
    rejected=0
    def convert(b,accept):
        global rejected
        exe.write_bytes(b)
        p=subprocess.run([str(converter),str(exe),str(rs)],capture_output=True,timeout=15)
        assert (p.returncode==0)==accept,(p.stderr,b[512:640].hex())
        if not accept:rejected+=1
    for spec in manifest['cases']:
        i=spec['id'];b=build(i);assert b==build(i) and len(b)==2048
        # Separate literal header/layout audit rather than parsing generator metadata.
        assert b[128:132]==b'PE\0\0' and b[134:136]==b'\x03\0'
        assert struct.unpack_from('<I',b,432)[0]==512  # second-section raw size
        assert b[1712:1723]==b'msvcrt.dll\0' and b[1730:1737]==b'_write\0'
        if i==0:
            assert b[1279]==33 and b[1024]==0  # buffer is the final declared virtual byte
        digest.update(b);exe.write_bytes(b)
        if not windows:
            convert(b,True);first=rs.read_bytes();convert(b,True);assert first==rs.read_bytes()
            subprocess.run(['rustc','-D','warnings',str(rs),'-o',str(elf)],check=True,timeout=30)
        with open(root/'out','wb') as out,open(root/'err','wb') as err:
            p=subprocess.run([str(exe if windows else elf)],stdout=out,stderr=err,timeout=15)
        observation=((root/'out').read_bytes().hex(),(root/'err').read_bytes().hex(),p.returncode)
        assert observation==(spec['stdout_hex'],spec['stderr_hex'],spec['exit']),(i,observation)
        print(f'corpus {i:02}: stdout={observation[0]} stderr={observation[1]} exit={observation[2]}')
        if not windows:
            for offset,value in [(1536,0x3080+i%8*4),(1548,0x30ff),(1552,0x30fc),(1600+i%8*4,0x80000001),(1024+(255 if i==0 else i%8),10)]:
                bad=bytearray(b);struct.pack_into('<I',bad,offset,value)
                if offset==1552: struct.pack_into('<I',bad,344,value)  # keep IAT directory equal: reach range check
                # Newline is only invalid if this payload is used; conservative path checks still see all imports.
                convert(bad,False)
    print(f'corpus version={VERSION} seed={SEED} instances=32 families=4 sha256={digest.hexdigest()} rejected={rejected}')
