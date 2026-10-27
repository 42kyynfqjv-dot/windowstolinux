"""Same original compiler PE; compare rejection only, never claim ELF execution."""
from pathlib import Path
import hashlib,json,subprocess,sys,tempfile
out=Path(sys.argv[1]).resolve();repo=Path(__file__).resolve().parents[2];r=json.loads((out/'report.json').read_text());pe=out/'ISCC.exe';assert hashlib.sha256(pe.read_bytes()).hexdigest()==r['compiler_sha256']
with tempfile.TemporaryDirectory() as td:
 target=Path(td)/'out.rs';target.write_text('preserve');p=subprocess.run([str(repo/'target/debug/w2l'),str(pe),str(target)],capture_output=True,timeout=30)
 assert p.returncode==1 and target.read_text()=='preserve'
 assert p.stderr.decode()==r['conversion']['stderr']
 (out/'native-rejection.json').write_text(json.dumps(dict(kind='same-PE rejection only; zero ELF comparisons',pe_sha256=r['compiler_sha256'],exit=p.returncode,diagnostic=p.stderr.decode()),indent=2)+'\n')
p=subprocess.run([str(repo/'target/debug/w2l'),'--inspect-image',str(pe)],capture_output=True,timeout=30)
assert p.returncode==r['inspection']['exit'] and p.stderr.decode()==r['inspection']['stderr']
print('Same-PE Windows/Linux intake rejection agrees; zero third-party ELF comparisons')
