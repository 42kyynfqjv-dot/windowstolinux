"""Independent guard/copy omissions must be detected by literal heap regressions."""
from pathlib import Path
import shutil
import subprocess
import tempfile

repo=Path(__file__).resolve().parents[3]
source=(repo/'src/guest_memory.rs').read_text()
mutations=[
 ('heap-identity','heap.process != self.identity','false'),
 ('allocation-origin','&& r.heap_allocation',''),
 ('zero-tail-preserves-unknown-prefix','defined[..n].copy_from_slice(&self.regions[i].defined[..n]);',''),
 ('copied-prefix','bytes[..n].copy_from_slice(&self.regions[i].bytes[..n]);',''),
 ('same-address-generation','self.regions[i] = Region {','let capability = Capability { generation: self.regions[i].capability.generation, ..capability };\nself.regions[i] = Region {'),
]
with tempfile.TemporaryDirectory() as tmp:
    d=Path(tmp)
    for f in ['guest_memory_tests.rs','guest_heap_tests.rs']:
        shutil.copyfile(repo/'src'/f,d/f)
    for name,old,new in mutations:
        assert source.count(old)==1,(name,source.count(old))
        (d/'core.rs').write_text(source.replace(old,new))
        p=subprocess.run(['rustc','--edition=2021','--test',str(d/'core.rs'),'-o',str(d/'core')],capture_output=True,timeout=45)
        assert p.returncode==0,(name,p.stderr.decode())
        p=subprocess.run([str(d/'core'),'heap_tests::'],capture_output=True,timeout=15)
        assert p.returncode!=0 and b'test result: FAILED' in p.stdout,(name,p.stdout,p.stderr)
print('Five heap guard/copy mutations detected; existing ten heap test functions reused, not five new tests')
