"""Original Windows API registration observations; no exception invocation/translation."""
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

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / 'corpus'))
from launch import execute


def validate(data, expected):
    words = [expected['magic'], *expected['checks']]
    if len(data) != len(words) * 4 or list(struct.unpack('<' + 'I' * len(words), data)) != words:
        raise ValueError('filter exchange identity/order mismatch')
    return len(words) - 1


def observe(output):
    if sys.platform != 'win32':
        raise RuntimeError('filter exchange observations require Windows')
    if not os.environ.get('VCToolsVersion', '').startswith('14.44.') or not os.environ.get('WindowsSDKVersion', '').startswith('10.0.26100.'):
        raise RuntimeError('MSVC14.44 / SDK10.0.26100 required')
    output.mkdir(parents=True, exist_ok=True)
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    names = ['filter_exchange_probe.c', 'filter-exchange-expectations.json', 'filter-exchange-frozen.json']
    for name in names:
        shutil.copyfile(HERE / name, output / name)
    for name, sha in json.loads((output / names[2]).read_text())['sources'].items():
        if digest(output / name) != sha:
            raise ValueError('filter frozen source mismatch')
    binary = output / 'filter-exchange.exe'
    flags = ['/nologo', '/O1', '/MT', '/W4', '/WX', str(output / names[0]), '/Fe:' + str(binary), '/Fo:' + str(output / 'filter.obj'), '/link', '/MACHINE:X86', '/SUBSYSTEM:CONSOLE', '/OPT:NOICF']
    report = dict(scope='original authored Windows exchange only; no callback invocation; zero translated pairs', status='started', observations=0, host=platform.platform(), compiler_version=os.environ['VCToolsVersion'], sdk=os.environ['WindowsSDKVersion'], compiler_sha256=digest(Path(shutil.which('cl'))), linker_sha256=digest(Path(shutil.which('link'))), sources={n: digest(output / n) for n in names}, flags=flags)
    def save():
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    save()
    try:
        built = subprocess.run(['cl', *flags], capture_output=True, timeout=120)
        (output / 'compile.stdout').write_bytes(built.stdout)
        (output / 'compile.stderr').write_bytes(built.stderr)
        if built.returncode:
            raise RuntimeError('filter exchange compilation failed')
        image = binary.read_bytes()
        nt = struct.unpack_from('<I', image, 60)[0]
        if image[:2] != b'MZ' or image[nt:nt + 4] != b'PE\x00\x00' or struct.unpack_from('<H', image, nt + 4)[0] != 0x14c or struct.unpack_from('<H', image, nt + 24)[0] != 0x10b:
            raise ValueError('filter probe is not PE32 x86')
        report['pe_sha256'] = digest(binary)
        save()
        result = execute([str(binary)], output / 'original.stdout', output / 'original.stderr', output / 'launch', dict(case='filter-exchange'), dict(exit=0, protocol='28-byte frozen distinct-target/exchange identities'), timeout=15)
        record = json.loads((output / 'launch/launch.json').read_text())
        if record.get('executed_sha256') != report['pe_sha256'] or digest(output / 'launch/program.bin') != report['pe_sha256'] or digest(binary) != report['pe_sha256']:
            raise ValueError('filter executed PE identity mismatch')
        if result.returncode or (output / 'original.stderr').read_bytes():
            raise ValueError('filter original execution failed')
        report['observations'] = validate((output / 'original.stdout').read_bytes(), json.loads((output / names[1]).read_text()))
        report.update(status='matched', stdout_sha256=digest(output / 'original.stdout'), launch_sha256=digest(output / 'launch/launch.json'))
    except Exception as error:
        report.update(status='failed', error=type(error).__name__ + ': ' + str(error))
        raise
    finally:
        save()
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('output', type=Path)
    print(json.dumps(observe(parser.parse_args().output.resolve())))
