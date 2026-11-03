"""Pinned raw BOOL observations; v1 remains a distinct truth-only experiment."""
import argparse
import json
from pathlib import Path
from observe_code_page import observe
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('output',type=Path);a=p.parse_args()
    print(json.dumps(observe(a.output.resolve(),source_name='code_page_raw_probe.c',expected_name='code-page-raw-expectations.json',frozen_name='code-page-raw-frozen.json')))
