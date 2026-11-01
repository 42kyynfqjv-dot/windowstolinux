"""Original authored Windows UTF-8 process/CRT observations; never translation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
from command_line_contract import HERE,vectors,decode_probe,validate_probe

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def record_result(report,record,result,row):
    record['exit']=result.returncode
    record['stdout_sha256']=hashlib.sha256(result.stdout).hexdigest()
    try:
        if result.returncode:raise ValueError('original probe exit failure')
        observed=decode_probe(result.stdout)
        record.update(observed_acp=observed['acp'],observed_stable=observed['stable'],observed_narrow_hex=observed['a'].hex(),observed_wide_hex=observed['w'].hex(),observed_argv_hex=[x.hex() for x in observed['argv']])
        actual=validate_probe(result.stdout,row)
    except ValueError as error:
        record.update(status='mismatch',error=str(error));raise
    record.update(status='matched',acp=actual['acp'],stable=actual['stable'],narrow_hex=actual['a'].hex(),wide_hex=actual['w'].hex(),argv_utf16le_hex=[x.hex() for x in actual['argv']])
    report['observations']+=1

def observe(output):
    if sys.platform!='win32':raise RuntimeError('original command-line observation requires Windows')
    if not os.environ.get('VCToolsVersion','').startswith('14.44.'):raise RuntimeError('MSVC14.44 toolchain environment required')
    output.mkdir(parents=True,exist_ok=True)
    exe=output/'command-line-probe.exe'
    flags=['/nologo','/O1','/MT','/W4','/WX','/utf-8',str(HERE/'command_line_probe.c'),'/Fe:'+str(exe),'/Fo:'+str(output/'command-line-probe.obj'),'/link','/MACHINE:X86','/SUBSYSTEM:CONSOLE','/MANIFEST:EMBED','/MANIFESTINPUT:'+str(HERE/'command_line_probe.manifest')]
    compiled=subprocess.run(['cl',*flags],capture_output=True,timeout=120)
    (output/'compile.stdout').write_bytes(compiled.stdout);(output/'compile.stderr').write_bytes(compiled.stderr)
    if compiled.returncode:raise RuntimeError('authored command-line probe compilation failed')
    report=dict(kind='original Windows API/CRT observations; no translation',toolchain_family='MSVC14.44',toolchain_version=os.environ['VCToolsVersion'],compiler_sha256=sha(Path(shutil.which('cl'))),linker_sha256=sha(Path(shutil.which('link'))),sdk_version=os.environ.get('WindowsSDKVersion'),flags=flags,host=platform.platform(),pe_sha256=sha(exe),source_sha256=sha(HERE/'command_line_probe.c'),manifest_sha256=sha(HERE/'command_line_probe.manifest'),vectors_sha256=sha(HERE/'command-line-vectors.json'),cases=[],observations=0,whole_pe_pairs=0)
    def save(): (output/'report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    save()
    for index,row in enumerate(vectors()):
        record=dict(index=index,raw_utf16le_hex=row['utf16le_hex'],status='started');report['cases'].append(record);save()
        try:
            result=subprocess.run(row['raw'],executable=str(exe),capture_output=True,timeout=15)
        except subprocess.TimeoutExpired as error:
            (output/f'case-{index}.stdout').write_bytes(error.stdout or b'');(output/f'case-{index}.stderr').write_bytes(error.stderr or b'');record['status']='timeout';save();raise
        except OSError as error:
            record.update(status='launch-error',error=str(error));save();raise
        (output/f'case-{index}.stdout').write_bytes(result.stdout);(output/f'case-{index}.stderr').write_bytes(result.stderr)
        try:record_result(report,record,result,row)
        finally:save()
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('output',type=Path);args=parser.parse_args();r=observe(args.output.resolve());print(json.dumps({'observations':r['observations'],'pe_sha256':r['pe_sha256'],'whole_pe_pairs':r['whole_pe_pairs']}))
