"""Original entry-state observation, with immutable artifact provenance."""
from pathlib import Path
import hashlib,json,subprocess,struct,sys
root=Path(sys.argv[1]).resolve()
out=Path(sys.argv[2]).resolve();out.mkdir(parents=True,exist_ok=False)
original=root/'rcedit.exe';data=original.read_bytes()
digest=hashlib.sha256(data).hexdigest()
if digest!='ce252fb1eddd05c3ea6acd73871995b1badd32446d76c6df07abaf8fa44fd22f':
    raise ValueError('original identity changed')
pe=struct.unpack_from('<I',data,60)[0];entry=struct.unpack_from('<I',data,pe+40)[0]
source=Path(__file__).with_name('observe_entry.c').resolve();observer=out/'observer.exe'
command=['cl','/nologo','/W4','/O2',str(source),'/Fe'+str(observer),'/Fo'+str(out/'observer.obj')]
build=subprocess.run(command,capture_output=True,timeout=60)
(out/'build.txt').write_bytes(build.stdout+build.stderr)
if build.returncode: raise RuntimeError('observer compilation failed')
run=subprocess.run([str(observer),str(original),str(entry)],capture_output=True,timeout=20)
(out/'stdout').write_bytes(run.stdout);(out/'stderr').write_bytes(run.stderr)
if run.returncode: raise RuntimeError('entry observation unavailable')
report=json.loads(run.stdout);report.update(pe_sha256=digest,source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),translated_pairs=0)
if report['eip']!=report['image_base']+entry: raise ValueError('not original entry')
if hashlib.sha256(original.read_bytes()).hexdigest()!=digest: raise ValueError('artifact changed')
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
