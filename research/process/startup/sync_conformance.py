"""Independent successful-call expectations; never an allocation-failure oracle."""
import json
from pathlib import Path

def projection(row):
    return {key:row[key] for key in ('initialized','events','reinitialized','canaries')}

def validate(row):
    expected=json.loads(Path(__file__).with_name('sync-frozen.json').read_text())['expected']
    if any(row[k] is not True for k in ('initialized','reinitialized','canaries')) or any(type(x) is not int for x in row['events']) or projection(row)!=expected:
        raise ValueError('critical-section conformance mismatch')
    return projection(row)
