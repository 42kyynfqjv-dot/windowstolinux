"""No PE execution: validate fixed samples, failed evidence and owned cleanup."""
from contextlib import redirect_stdout
import io
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "corpus"))
sys.path.insert(0, str(ROOT / "scripts"))
from windows_original_contexts import run_contexts
from make_output_probe import output_probe
from generate import build


class OriginalContexts(unittest.TestCase):
    def test_changed_frozen_original_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError,"image changed"):
                run_contexts(directory, directory, output_probe()+b"changed", build(0), build(1),
                             executor=lambda *args, **kwargs:self.fail("changed image executed"))

    def test_exact_plan_and_timeout_are_not_retried_or_counted_as_success(self):
        for failure in (None, "timeout", "output", "hash", "exit", "stage"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); calls = []; image_paths = []
                images = (output_probe(), build(0), build(1))

                def fake(command, stdout, stderr, evidence, identity, expected, timeout):
                    index = len(calls); calls.append((command, dict(identity), timeout))
                    image = Path(command[0]).read_bytes(); image_paths.append(Path(command[0]))
                    self.assertEqual(timeout, 15)
                    self.assertEqual(hashlib.sha256(image).hexdigest(), identity["pe_sha256"])
                    self.assertEqual(Path(command[0]).name, "output-probe.exe" if identity["case"] == "output-probe" else "case.exe")
                    evidence.mkdir(parents=True)
                    (evidence / "program.bin").write_bytes(image)
                    record = dict(identity, executed_sha256=identity["pe_sha256"],
                                  stage="finished", timeout=False, exit=0,
                                  stdout_hex=expected["stdout_hex"], stderr_hex="")
                    self.assertEqual(expected, dict(exit=0,stdout_hex={"corpus0":"21","corpus1":"433031","output-probe":"48656c6c6f"}[identity["case"]],stderr_hex=""))
                    if index == 1 and failure == "timeout":
                        record.update(stage="failed", timeout=True, poll_at_timeout=None,
                                      failure="TimeoutExpired: retained original")
                        record.pop("exit")
                    if index == 1:
                        if failure == "output": record["stdout_hex"] = "00"
                        if failure == "hash": record["executed_sha256"] = "0"*64
                        if failure == "exit": record["exit"] = 1
                        if failure == "stage": record["stage"] = "failed"
                    (evidence / "launch.json").write_text(json.dumps(record))
                    if index == 1 and failure == "timeout":
                        raise subprocess.TimeoutExpired(command, 15)

                with redirect_stdout(io.StringIO()):
                    records = run_contexts(root / "evidence", root, *images, executor=fake)
                self.assertEqual(len(calls), 9)
                self.assertEqual([x[1]["case"] for x in calls],
                                 ["corpus0", "corpus1", "output-probe"] * 3)
                self.assertEqual(sum(r["passed"] for r in records), 9 if failure is None else 8)
                for repetition in range(3):
                    self.assertEqual(calls[3*repetition][0], calls[3*repetition+1][0])
                    self.assertEqual([x[1]["repetition"] for x in calls[3*repetition:3*repetition+3]], [repetition]*3)
                self.assertTrue(all(not p.exists() for p in image_paths))
                if failure is not None:
                    self.assertEqual(records[1]["timeout"], failure == "timeout")
                    self.assertFalse(records[1]["passed"])
                    self.assertEqual((root / "evidence/sample-2/program.bin").read_bytes(), images[2])


if __name__ == "__main__":
    unittest.main()
