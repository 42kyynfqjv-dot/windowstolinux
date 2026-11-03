"""Fixed owned-copy experiments for exact original images; every sample counts."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from launch import execute


def run_contexts(root, checkout, output_image, corpus_zero, corpus_one,
                 executor=execute):
    frozen = json.loads(Path(__file__).with_name("windows-original-contexts.json").read_text())
    for name, image in [("output-probe", output_image), ("corpus0", corpus_zero), ("corpus1", corpus_one)]:
        if hashlib.sha256(image).hexdigest() != frozen["images"][name]:
            raise ValueError("frozen original context image changed: " + name)
    root, checkout = Path(root), Path(checkout)
    root.mkdir(parents=True, exist_ok=True)
    records = []

    def sample(exe, image, expected, name, repetition, context):
        exe.write_bytes(image)
        evidence = root / f"sample-{len(records)+1}"
        identity = dict(case=name, repetition=repetition, context=context,
                        pe_sha256=hashlib.sha256(image).hexdigest(),
                        scope="original authored PE only; no converter execution")
        try:
            executor([str(exe)], evidence.parent / "stdout",
                     evidence.parent / "stderr", evidence, identity,
                     dict(exit=0, stdout_hex=expected.hex(), stderr_hex=""), timeout=15)
        except subprocess.TimeoutExpired:
            pass  # Retain failed sample; continue only the predefined matrix.
        record = json.loads((evidence / "launch.json").read_text())
        record["passed"] = (record.get("stage") == "finished"
                            and record.get("timeout") is False
                            and record.get("exit") == 0
                            and record.get("stdout_hex") == expected.hex()
                            and record.get("stderr_hex") == ""
                            and record.get("executed_sha256") == identity["pe_sha256"])
        records.append(record)
        (root / "report.json").write_text(json.dumps(records, indent=2) + "\n")
        print("exact original context result " + json.dumps(record), flush=True)

    for repetition in range(3):
        # Match corpus/check.py: system-temp directory, same case.exe overwritten
        # from case0 to case1, unchanged inherited working directory and handles.
        with tempfile.TemporaryDirectory(prefix="w2l-exact-corpus-") as directory:
            exe = Path(directory) / "case.exe"
            sample(exe, corpus_zero, b"!", "corpus0", repetition, "system-temp-case-sequence")
            sample(exe, corpus_one, b"C01", "corpus1", repetition, "system-temp-case-sequence")
        # Owned directory on the checkout volume and the exact probe basename.
        # Full historical paths/VM state are not reproduced by this control.
        with tempfile.TemporaryDirectory(prefix="w2l-exact-output-", dir=checkout) as directory:
            sample(Path(directory) / "output-probe.exe", output_image, b"Hello",
                   "output-probe", repetition, "checkout-volume-owned-copy")
    return records
