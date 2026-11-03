"""Independent host-runtime exit controls; never translated-PE evidence."""
import json
from pathlib import Path
import subprocess
import sys
from launch import execute


def run_controls(root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    records = []
    # os.write avoids Python buffering in both cases. Only termination differs.
    for name, suffix in [('normal-runtime-exit', ''), ('immediate-exit', '; os._exit(0)')]:
        evidence = root / name
        command = [sys.executable, '-c', "import os; os.write(1,b'Hello')" + suffix]
        try:
            execute(command, root/'stdout', root/'stderr', evidence,
                    {'control': name, 'scope': 'host Python runtime, not 32-bit fixture CRT'},
                    {'exit': 0, 'stdout_hex': b'Hello'.hex(), 'stderr_hex': ''}, timeout=15)
        except subprocess.TimeoutExpired:
            pass  # Keep failure; run the other predefined control without retry.
        record = json.loads((evidence/'launch.json').read_text())
        record['passed'] = (not record['timeout'] and record.get('exit') == 0
                            and record.get('stdout_hex') == b'Hello'.hex()
                            and record.get('stderr_hex') == '')
        records.append(record)
        (root/'report.json').write_text(json.dumps(records, indent=2)+'\n')
    return records
