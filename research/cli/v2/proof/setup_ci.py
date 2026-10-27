"""Resolve the hash-pinned official wheel's native executable for CI commands."""
import os,shutil,subprocess,sys
from pathlib import Path
name='z3.exe' if os.name=='nt' else 'z3'
paths=[Path(sys.executable).parent/name,Path(sys.executable).parent/'Scripts'/name,Path(sys.prefix)/'bin'/name]
found=next((p for p in paths if p.is_file()),None)
if found is None:
 found=shutil.which(name)
assert found,'pinned Z3 executable missing'
found=str(Path(found).resolve())
p=subprocess.run([found,'-version'],capture_output=True,text=True,timeout=3)
assert p.returncode==0 and p.stdout.strip()=='Z3 version 4.15.4 - 64 bit',p.stdout
with open(os.environ['GITHUB_ENV'],'a',encoding='utf-8') as f:f.write('W2L_Z3='+found+'\n')
print('Pinned local compiler solver:',p.stdout.strip())
