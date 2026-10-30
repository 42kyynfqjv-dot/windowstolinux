"""Freeze/replay independent original-Windows unwind and manual restore evidence.

Extraction validates complete independently specified instruction encodings, not
a scan for RET bytes or a fixed unverified length. No production lifter is used.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys

from inventory import mapped_bytes
from coff_binding import dispatcher_evidence

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / 'corpus'))
from launch import execute


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def cleanup_instructions(digit, delta):
    # Equivalent x86 register/register ADD encodings are allowed; every
    # immediate and memory operand is checked independently of the converter.
    return [
        ['8b4c2404'], ['8b01'],
        *([['03c0', '01c0']] * 4),
        [f'83c0{digit:02x}', '05' + struct.pack('<I', digit).hex()],
        ['8901'], [f'834104{delta:02x}'], ['c3'],
    ]


RESTORE_INSTRUCTIONS = [
    ['8b4c2404'], ['8b81b0000000'], ['8ba1c4000000'],
    ['8ba9b4000000'], ['ffa1b8000000'],
]


def verified_code(read, instructions):
    """Read exactly each expected instruction, rejecting other forms/operands."""
    code = bytearray()
    for options in instructions:
        matches = []
        for option in options:
            candidate = bytes.fromhex(option)
            try:
                observed = read(len(code), len(candidate))
            except (ValueError, struct.error):
                continue
            if observed == candidate:
                matches.append(candidate)
        if len(matches) != 1:
            raise ValueError(f'unsupported or ambiguous probe instruction at byte {len(code)}')
        code.extend(matches[0])
    return bytes(code)


def extract(data, base, rva, instructions, name, out):
    if type(rva) is not int or not 0 < rva < 2**32:
        raise ValueError('invalid symbol RVA')
    code = verified_code(lambda offset, size: mapped_bytes(data, base+rva+offset, size), instructions)
    filename = name + '.bin'
    (out / filename).write_bytes(code)
    return dict(name=name, rva=rva, size=len(code), code_hex=code.hex(),
                sha256=sha256(code), file=filename)


def main(out):
    frozen = json.loads((HERE / 'unwind-frozen.json').read_text())
    source = HERE / 'unwind_probe.c'
    if sha256(source.read_bytes()) != frozen['source_sha256']:
        raise ValueError('frozen unwind source identity changed')
    out.mkdir(parents=True, exist_ok=False)
    (out / 'unwind_probe.c').write_bytes(source.read_bytes())
    (out / 'unwind-frozen.json').write_bytes((HERE / 'unwind-frozen.json').read_bytes())
    compiler = shutil.which('cl')
    if not compiler:
        raise RuntimeError('official x86 MSVC environment is unavailable')
    version = subprocess.run([compiler], capture_output=True, timeout=10)
    (out / 'compiler-version.txt').write_bytes(version.stdout + version.stderr)
    exe = out / 'unwind.exe'
    command = ['cl', *frozen['compiler_flags'], str(source),
               '/Fe'+str(exe), '/Fo'+str(out / 'unwind.obj')]
    build = subprocess.run(command, capture_output=True, timeout=60)
    (out / 'build.txt').write_bytes(build.stdout + build.stderr)
    if build.returncode:
        raise RuntimeError('unwind probe compilation failed: '+(build.stdout+build.stderr).decode(errors='replace'))
    if sha256(source.read_bytes()) != frozen['source_sha256']:
        raise ValueError('source changed during compilation')
    disasm = subprocess.run(['dumpbin', '/disasm', str(exe)], capture_output=True, timeout=60)
    (out / 'disasm.txt').write_bytes(disasm.stdout + disasm.stderr)
    if disasm.returncode:
        raise RuntimeError('unwind probe disassembly failed')
    data = exe.read_bytes()
    digest = sha256(data)
    report = dict(
        kind='original Windows SEH plus separate manual restore; no whole-PE translated pair',
        platform=platform.platform(), command=command,
        source_sha256=frozen['source_sha256'], pe_sha256=digest,
        compiler_path=compiler, compiler_sha256=sha256(Path(compiler).read_bytes()),
        vc_tools_version=os.environ.get('VCToolsVersion'),
        windows_sdk_version=os.environ.get('WindowsSDKVersion'),
        expected=frozen['expected_observation'], limits=frozen['limits'])
    report_path = out / 'report.json'
    report_path.write_text(json.dumps(report, indent=2)+'\n')
    result = execute([str(exe)], out / 'stdout', out / 'stderr', out / 'launch',
                     {'pe_sha256': digest, 'case': 'nested-unwind-and-manual-restore'},
                     frozen, timeout=10)
    report.update(exit=result.returncode, stdout_hex=(out/'stdout').read_bytes().hex(),
                  stderr_hex=(out/'stderr').read_bytes().hex())
    report_path.write_text(json.dumps(report, indent=2)+'\n')
    if result.returncode != frozen['expected_exit'] or report['stderr_hex'] != frozen['expected_stderr_hex']:
        raise ValueError('original Windows outcome differs from frozen expectation')
    observed = json.loads((out/'stdout').read_text())
    report['observation'] = observed
    report_path.write_text(json.dumps(report, indent=2)+'\n')
    if any(type(observed.get(k)) is not int or observed[k] != v
           for k, v in frozen['expected_observation'].items()):
        raise ValueError('independent unwind or restore expectation failed')
    if sha256(exe.read_bytes()) != digest:
        raise ValueError('executed PE identity changed')
    pe = struct.unpack_from('<I', data, 60)[0]
    if data[pe:pe+4] != b'PE\0\0' or struct.unpack_from('<H', data, pe+4)[0] != 0x14c:
        raise ValueError('expected x86 PE')
    if struct.unpack_from('<H', data, pe+24)[0] != 0x10b:
        raise ValueError('expected PE32 optional header')
    base = struct.unpack_from('<I', data, pe+52)[0]
    report['image_base'] = base  # Preferred base; runtime symbols were normalized to RVAs.
    rvas = observed.get('cleanup_rvas')
    if not isinstance(rvas, list) or len(rvas) != 3 or len(set(rvas)) != 3:
        raise ValueError('three distinct cleanup symbol RVAs required')
    cleanups = []
    for expected, rva in zip(frozen['scope_rows'], rvas):
        cleanups.append(extract(data, base, rva,
            cleanup_instructions(expected['trace_digit'], expected['local_delta']), expected['target'], out))
    restore = extract(data, base, observed['restore_rva'], RESTORE_INSTRUCTIONS, 'Restore', out)
    table_rva = observed['table_rva']
    if type(table_rva) is not int or table_rva <= 0:
        raise ValueError('invalid table RVA')
    table = mapped_bytes(data, base+table_rva, len(rvas)*frozen['scope_row_bytes'])
    rows = []
    for expected, rva in zip(frozen['scope_rows'], rvas):
        index = expected['index']
        parent, target = struct.unpack_from('<iI', table, index*8)
        if parent != expected['parent'] or target != base+rva:
            raise ValueError('retained PE authored scope table differs from measured symbol RVAs')
        rows.append(dict(index=index, parent=parent, target_rva=rva, owner=expected['owner']))
    # The target is original mapped code, not a synthesized Linux-only address.
    target_rva = observed['restore_target_rva']
    if type(target_rva) is not int or target_rva <= 0:
        raise ValueError('invalid original restore target RVA')
    target_prefix = mapped_bytes(data, base+target_rva, 1)
    (out/'scope-table.bin').write_bytes(table)
    report.update(table_rva=table_rva, scope_rows=rows, scope_table_hex=table.hex(),
                  scope_table_size=len(table), scope_table_sha256=sha256(table),
                  cleanups=cleanups, restore=restore, restore_target_rva=target_rva,
                  restore_target_first_byte=target_prefix.hex())
    dispatcher = dispatcher_evidence((out/'unwind.obj').read_bytes(), data, table_rva)
    (out/dispatcher['file']).write_bytes(bytes.fromhex(dispatcher['code_hex']))
    report['dispatcher'] = dispatcher
    report_path.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve())
