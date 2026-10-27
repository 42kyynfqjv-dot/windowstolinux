"""Same untouched source-built PE intake; no native utility execution claim."""
from pathlib import Path
import hashlib,json,subprocess,sys,tempfile
out=Path(sys.argv[1]).resolve();repo=Path(__file__).resolve().parents[3];r=json.loads((out/'report.json').read_text());pe=out/'rcedit.exe';assert hashlib.sha256(pe.read_bytes()).hexdigest()==r['utility_sha256']
with tempfile.TemporaryDirectory() as td:
 target=Path(td)/'out.rs';target.write_text('preserve');p=subprocess.run([str(repo/'target/debug/w2l'),str(pe),str(target)],capture_output=True,timeout=30)
 assert p.returncode==1 and target.read_text()=='preserve' and p.stderr.decode()==r['conversion']['stderr']
 record=dict(kind='same-PE intake rejection; zero ELF execution pairs',pe_sha256=r['utility_sha256'],diagnostic=p.stderr.decode())
 p=subprocess.run([str(repo/'target/debug/w2l'),'--inspect-image',str(pe)],capture_output=True,timeout=30)
 assert p.returncode==r['inspection']['exit'] and p.stderr.decode()==r['inspection']['stderr']
 record['inspection']=dict(exit=p.returncode,stdout=p.stdout.decode(),stderr=p.stderr.decode());(out/'native-rejection.json').write_text(json.dumps(record,indent=2)+'\n')
print('Original rcedit PE hashes/rejections agree; zero ELF execution pairs')
