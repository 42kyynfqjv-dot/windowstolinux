"""Check that both CI runners exercise every positive authored fixture equally."""
import re
from pathlib import Path
from make_pe32_fixture import CASES

workflow = Path(__file__).resolve().parents[1] / '.github/workflows/ci.yml'
text = workflow.read_text()
linux = re.search(r'for specification in (.*); do', text).group(1).split()
windows = re.findall(r"Name = '([^']+)'; Expected = (\d+)", text)
linux_pairs = [(name, int(code)) for name, code in (pair.split(':') for pair in linux)]
windows_pairs = [(name, int(code)) for name, code in windows]
assert len(dict(linux_pairs)) == len(linux_pairs), 'duplicate Linux case'
assert len(dict(windows_pairs)) == len(windows_pairs), 'duplicate Windows case'
assert dict(linux_pairs) == dict(windows_pairs), 'platform expectation mismatch'
assert set(dict(linux_pairs)) == set(CASES) - {'out_of_range'}, 'fixture coverage mismatch'
assert all(0 <= code <= 255 for _, code in linux_pairs), 'invalid expected exit status'
print(f'{len(linux_pairs)} fixture expectations agree across Windows, Linux and authored cases')
