"""Frozen authored x86 API conformance; no converter or target ACP assumption."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[2]/'corpus'))
from launch import execute

def validate(data,expected):
    rows=expected['cases']
    if len(data)!=12+12*len(rows):raise ValueError('code-page output extent')
    magic,acp,count=struct.unpack_from('<III',data)
    if magic!=expected['magic'] or count!=len(rows):raise ValueError('code-page output header')
    result=[]
    for i,row in enumerate(rows):
        page,valid,last_error=struct.unpack_from('<III',data,12+i*12)
        if page!=row['code_page'] or valid!=row['valid']:raise ValueError('code-page semantic mismatch')
        result.append(dict(code_page=page,valid=valid,last_error=last_error))
    return dict(observed_acp=acp,cases=result)

def validate_identity(output,expected_sha):
    launch=output/'launch'
    record=json.loads((launch/'launch.json').read_text(encoding='utf-8'))
    if record.get('executed_sha256')!=expected_sha or any(hashlib.sha256(p.read_bytes()).hexdigest()!=expected_sha for p in [launch/'program.bin',output/'code-page-probe.exe']):
        raise ValueError('code-page executed PE identity mismatch')

def observe(output, *, source_name="code_page_probe.c", expected_name="code-page-expectations.json", frozen_name="code-page-frozen.json"):
    if sys.platform!='win32':raise RuntimeError('code-page observation requires Windows')
    if not os.environ.get('VCToolsVersion','').startswith('14.44.'):raise RuntimeError('MSVC14.44 required')
    if not os.environ.get('WindowsSDKVersion','').startswith('10.0.26100.'):raise RuntimeError('Windows SDK10.0.26100 required')
    output.mkdir(parents=True,exist_ok=True)
    for name in [source_name,expected_name,frozen_name]:shutil.copyfile(HERE/name,output/name)
    sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    frozen=json.loads((output/frozen_name).read_text(encoding='utf-8'))
    for name,digest in frozen['sources'].items():
        if sha(output/name)!=digest:raise ValueError('code-page frozen source mismatch')
    flags=['/nologo','/O1','/MT','/W4','/WX',str(output/source_name),'/Fe:'+str(output/'code-page-probe.exe'),'/Fo:'+str(output/'code-page-probe.obj'),'/link','/MACHINE:X86','/SUBSYSTEM:CONSOLE']
    report=dict(scope='original authored Windows API only; zero translated pairs',host=platform.platform(),compiler_version=os.environ['VCToolsVersion'],sdk=os.environ.get('WindowsSDKVersion'),compiler_sha256=sha(Path(shutil.which('cl'))),linker_sha256=sha(Path(shutil.which('link'))),sources={n:sha(output/n) for n in [source_name,expected_name]},flags=flags,status='started',observations=0)
    def save():(output/'report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    save()
    try:
        built=subprocess.run(['cl',*flags],capture_output=True,timeout=120)
        (output/'compile.stdout').write_bytes(built.stdout);(output/'compile.stderr').write_bytes(built.stderr)
        if built.returncode:raise RuntimeError('code-page probe build failed')
        report['pe_sha256']=sha(output/'code-page-probe.exe');save()
        original=execute([str(output/'code-page-probe.exe')],output/'original.stdout',output/'original.stderr',output/'launch',dict(case='code-page-conformance',scope='original authored Windows API only'),dict(exit=0,protocol='36-byte independently frozen code-page record'),timeout=15)
        validate_identity(output,report['pe_sha256'])
        report['launch_sha256']=sha(output/'launch/launch.json')
        stdout=(output/'original.stdout').read_bytes();stderr=(output/'original.stderr').read_bytes()
        report['exit']=original.returncode;report['stdout_sha256']=hashlib.sha256(stdout).hexdigest()
        if original.returncode or stderr:raise ValueError('code-page original execution failed')
        report.update(validate(stdout,json.loads((output/expected_name).read_text(encoding='utf-8'))))
        report.update(status='matched',observations=len(report['cases']))
    except Exception as error:
        report.update(status='failed',error=type(error).__name__+': '+str(error));raise
    finally:save()
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('output',type=Path);args=p.parse_args();print(json.dumps(observe(args.output.resolve())))
