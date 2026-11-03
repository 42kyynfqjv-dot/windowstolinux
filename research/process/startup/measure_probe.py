"""Original Windows observations, deliberately separate from translation evidence."""
from pathlib import Path
import hashlib
import json
import platform
import shutil
import subprocess
import sys

here = Path(__file__).resolve().parent
frozen = json.loads((here/'probe-frozen.json').read_text())
assert hashlib.sha256((here/'probe.c').read_bytes()).hexdigest() == frozen['source_sha256']
out = Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=False)
exe = out/'probe.exe'
command = ['cl', '/nologo', '/W4', '/O2', '/GS', str(here/'probe.c'), '/Fe'+str(exe), '/Fo'+str(out/'probe.obj')]
build = subprocess.run(command, capture_output=True, timeout=60)
(out/'build.txt').write_bytes(build.stdout+build.stderr)
assert build.returncode == 0
rows = []
report = dict(kind='original Windows SEH probes; zero PE/ELF pairs',
              platform=platform.platform(), source_sha256=frozen['source_sha256'],
              compiler_path=shutil.which('cl'),
              compiler_sha256=hashlib.sha256(Path(shutil.which('cl')).read_bytes()).hexdigest(),
              pe_sha256=hashlib.sha256(exe.read_bytes()).hexdigest(), command=command, observations=rows)
for case in frozen['cases']:
    p = subprocess.run([str(exe), case['mode']], capture_output=True, timeout=10)
    rows.append(dict(mode=case['mode'], exit=p.returncode, stdout_hex=p.stdout.hex(), stderr_hex=p.stderr.hex()))
    (out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    assert (p.returncode, p.stdout.hex(), p.stderr) == (case['exit'], case['stdout_hex'], b'')
print(json.dumps(report, indent=2))
