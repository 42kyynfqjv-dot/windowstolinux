"""Official hash-pinned portable tool payload in ephemeral Windows runner storage."""
from pathlib import Path
import hashlib,json,os,subprocess,sys,urllib.request
assert os.name=='nt','Windows hosted runner required'
here=Path(__file__).resolve().parent;out=Path(sys.argv[1]).resolve();temp=Path(os.environ['RUNNER_TEMP']).resolve();assert out.is_relative_to(temp)
out.mkdir(parents=True,exist_ok=True);m=json.loads((here/'package.json').read_text());installer=out/m['asset']
urllib.request.urlretrieve(m['url'],installer)
assert hashlib.sha256(installer.read_bytes()).hexdigest()==m['sha256']
payload=out/'payload';assert not payload.exists(),'require fresh isolated directory'
args=[str(installer),'/CURRENTUSER','/PORTABLE=1','/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/NOICONS','/TASKS=','/DIR='+str(payload),'/LOG='+str(out/'portable-setup.log')]
(out/'prepare-command.json').write_text(json.dumps(args,indent=2))
p=subprocess.run(args,capture_output=True,timeout=120);(out/'prepare-stdout.bin').write_bytes(p.stdout);(out/'prepare-stderr.bin').write_bytes(p.stderr)
assert p.returncode==0,('portable payload preparation failed',p.returncode)
assert (payload/'ISCC.exe').is_file() and (payload/'ISCmplr.dll').is_file()
# Keep the package license beside the copied, untouched compiler artifact.
import shutil
shutil.copy2(payload/'ISCC.exe',out/'ISCC.exe');shutil.copy2(payload/'license.txt',out/'license.txt')
rows=[dict(path=str(f.relative_to(payload)),bytes=f.stat().st_size,sha256=hashlib.sha256(f.read_bytes()).hexdigest()) for f in sorted(payload.rglob('*')) if f.is_file()]
(out/'payload-manifest.json').write_text(json.dumps(rows,indent=2)+'\n')
print('Official portable payload verified; no generated installer executed')
