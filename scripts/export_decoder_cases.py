"""Export current authored instruction streams for isolated decoder evaluation."""
from pathlib import Path
from make_pe32_fixture import CASES

output = Path(__file__).resolve().parents[1] / 'tools/decoder-eval/cases.tsv'
output.write_text(''.join(f'{name}\t{code.hex()}\n' for name, code in sorted(CASES.items()) if name != 'out_of_range'))
print(f'exported {len(CASES)-1} authored streams to {output}')
