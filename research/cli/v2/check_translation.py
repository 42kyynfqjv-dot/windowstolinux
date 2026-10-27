"""Same unchanged Windows PE -> Rust -> ELF; compare frozen original observations."""
import hashlib,json,os,subprocess,sys,tempfile
from pathlib import Path
root=Path(sys.argv[1]).resolve();repo=Path(__file__).resolve().parents[3];src=Path(__file__).resolve().parent
report=json.loads((root/'report.json').read_text());cases=json.loads((src/'cases.json').read_text());extra=json.loads((src/'extra-failures.json').read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def record(p,name):return dict(name=name,exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex())
results=[]
with tempfile.TemporaryDirectory() as td:
 d=Path(td)
 for row in report['programs']:
  name='uppercase_v2_'+row['config'];pe=root/(name+'.exe');assert sha(pe)==row['pe_sha256']
  generated=d/(name+'.rs');exe=d/name
  p=subprocess.run([str(repo/'target/debug/w2l'),str(pe),str(generated)],capture_output=True,timeout=30);assert p.returncode==0,p.stderr
  assert sha(generated)==row['conversion']['rust_sha256'] and generated.read_bytes()==(root/(name+'.rs')).read_bytes()
  p=subprocess.run(['rustc','--edition=2021',str(generated),'-o',str(exe)],capture_output=True,timeout=30);assert p.returncode==0,p.stderr
  actual=[]
  for mode,key in [('file','observations'),('pipe','pipe_observations')]:
   for v,original in zip(cases,row[key],strict=True):
    payload=bytes.fromhex(v['input_hex']);path=d/'input.bin';path.write_bytes(payload)
    if mode=='file':
     with path.open('rb') as f:p=subprocess.run([str(exe)],stdin=f,capture_output=True,timeout=30)
    else:p=subprocess.run([str(exe)],input=payload,capture_output=True,timeout=30)
    got=record(p,v['name']);assert got==original=={k:v[k] for k in got},(mode,got)
    actual.append(dict(kind=mode,**got))
  path=d/'input.bin';path.write_bytes(b'a')
  with path.open('wb') as f:p=subprocess.run([str(exe)],stdin=f,capture_output=True,timeout=30)
  got=dict(exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex());assert got==row['read_failure'];actual.append(dict(kind='read-failure',**got))
  path.write_bytes(b'a')
  with path.open('rb') as f,path.open('rb') as dest:p=subprocess.run([str(exe)],stdin=f,stdout=dest,stderr=subprocess.PIPE,timeout=30)
  got=dict(exit=p.returncode,destination_after_hex=path.read_bytes().hex(),stderr_hex=p.stderr.hex());assert got==row['write_failure'];actual.append(dict(kind='write-failure',**got))
  path.write_bytes(bytes.fromhex(extra['closed_output_pipe']['input_hex']));rd,wr=os.pipe();os.close(rd)
  with path.open('rb') as f,os.fdopen(wr,'wb',buffering=0) as dest:p=subprocess.run([str(exe)],stdin=f,stdout=dest,stderr=subprocess.PIPE,timeout=30)
  got=dict(exit=p.returncode,stderr_hex=p.stderr.hex(),stdout=extra['closed_output_pipe']['stdout']);assert got==row['closed_output_pipe'];actual.append(dict(kind='closed-output-pipe',**got))
  # Independent native-adapter contract: a failed pipe write must expose
  # ERROR_BROKEN_PIPE to admitted subsequent GetLastError predicates.
  adapter=d/'adapter.rs';adapter_exe=d/'adapter'
  adapter.write_text(generated.read_text().replace('fn main(){','fn original_main(){')+'\nfn main(){let mut io=Native::new();assert_eq!(io.write(2,b"x"),Err(109));}\n')
  p=subprocess.run(['rustc','--edition=2021',str(adapter),'-o',str(adapter_exe)],capture_output=True,timeout=30);assert p.returncode==0,p.stderr
  rd,wr=os.pipe();os.close(rd)
  with os.fdopen(wr,'wb',buffering=0) as dest:p=subprocess.run([str(adapter_exe)],stdout=dest,stderr=subprocess.PIPE,timeout=30)
  assert p.returncode==0 and not p.stderr,p.stderr
  # The same emitted instruction function with a substituted backend: eight
  # documented-result probes, not additional unchanged Windows executions.
  (d/'generated.rs').write_bytes(generated.read_bytes())
  (d/'scripted.rs').write_bytes((src/'scripted_native.rs').read_bytes())
  p=subprocess.run(['rustc','--edition=2021',str(d/'scripted.rs'),'-o',str(d/'scripted')],capture_output=True,timeout=30);assert p.returncode==0,p.stderr
  p=subprocess.run([str(d/'scripted')],capture_output=True,timeout=30);assert p.returncode==0 and not p.stderr,p.stderr
  scripted=[]
  for line in p.stdout.decode().splitlines():
   mode,code,reads,writes,count=map(int,line.split());got=dict(mode=mode,exit=code,reads=reads,writes=writes,output_bytes=count)
   assert got==report['scripted_probe']['records'][mode],got
   scripted.append(got)
  assert len(scripted)==8
  results.append(dict(config=row['config'],pe_sha256=sha(pe),rust_sha256=sha(generated),observations=actual,scripted_native=scripted))
 (root/'translation-native.json').write_text(json.dumps(dict(kind='unchanged PE -> Rust -> ELF',programs=results),indent=2)+'\n')
print('2 unchanged compiler PEs;62 real Windows/ELF file/pipe/failure comparisons;identical generated Rust')
