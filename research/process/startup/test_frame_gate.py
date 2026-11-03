"""Required CI provenance gates; no altered executable is ever run."""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from check_frame import (check, require_cross_host_result, sha,
                         verify_windows_files, windows_reference)

ARTIFACT = None
if '--artifact' in sys.argv:
    index=sys.argv.index('--artifact')
    ARTIFACT=Path(sys.argv[index+1]).resolve()
    del sys.argv[index:index+2]


class RequiredGateTests(unittest.TestCase):
    def test_required_missing_artifact_fails_before_compiler(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);out=root/'linux-output'
            with self.assertRaisesRegex(ValueError,'required retained Windows component report is missing'):
                check(root,root/'nonexistent-compiler',out,require_windows_component=True)
            self.assertFalse(out.exists())

    def test_required_self_report_cannot_substitute_for_windows(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);out=root/'frame-native-windows'
            with self.assertRaisesRegex(ValueError,'cannot be its own current output'):
                check(root,root/'nonexistent-compiler',out,require_windows_component=True)
            self.assertFalse(out.exists())

    def test_unavailable_local_and_windows_mode_are_explicit(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            self.assertIsNone(windows_reference(root,root/'linux-output',False))
            self.assertIsNone(windows_reference(root,root/'frame-native-windows',False))
            require_cross_host_result({'cross_host_rust_identical':None},False)

    def test_required_postcondition_rejects_null_false_missing_or_one(self):
        for value in [None,False,1,'true']:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    require_cross_host_result({'cross_host_rust_identical':value,'cross_host_same_original_pe':True},True)
                with self.assertRaises(ValueError):
                    require_cross_host_result({'cross_host_rust_identical':True,'cross_host_same_original_pe':value},True)
        with self.assertRaises(ValueError):require_cross_host_result({},True)
        require_cross_host_result({'cross_host_rust_identical':True,'cross_host_same_original_pe':True},True)


class RetainedWindowsEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if ARTIFACT is None:
            raise unittest.SkipTest('pass --artifact ORIGINAL_DIRECTORY for retained Windows mutation checks')
        cls.original=ARTIFACT/'frame-native-windows'
        cls.info=dict(pe_sha256=sha((ARTIFACT/'unwind.exe').read_bytes()),
                      source_sha256=sha((ARTIFACT/'unwind_probe.c').read_bytes()),
                      object_sha256=sha((ARTIFACT/'unwind.obj').read_bytes()))

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='w2l-frame-gate-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'windows'
        shutil.copytree(self.original,self.root)

    def test_valid_retained_original_files(self):
        # This tests recorded artifact consistency, not a new Windows execution
        # or eligibility under any newer native conformance suite.
        prior,source=verify_windows_files(self.root,self.info)
        self.assertEqual(sha(source),prior['rust_sha256'])

    def test_tampered_generated_rust_file_rejected(self):
        source=self.root/'frame.rs';source.write_bytes(source.read_bytes()+b'\n// mutation\n')
        with self.assertRaisesRegex(ValueError,'actual file provenance'):
            verify_windows_files(self.root,self.info)

    def test_tampered_original_hash_report_rejected(self):
        path=self.root/'native-frame-report.json';report=json.loads(path.read_text())
        report['pe_sha256']='0'*64;path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError,'different original pe_sha256'):
            verify_windows_files(self.root,self.info)

    def test_failed_launch_cannot_be_a_pass(self):
        path=self.root/'native-launch/launch.json';launch=json.loads(path.read_text())
        launch.update(stage='failed',timeout=True);path.write_text(json.dumps(launch))
        with self.assertRaisesRegex(ValueError,'completion evidence is incomplete'):
            verify_windows_files(self.root,self.info)

    def test_executed_binary_hash_must_match(self):
        path=self.root/'native-launch/program.bin';path.write_bytes(path.read_bytes()+b'\0')
        with self.assertRaisesRegex(ValueError,'completion evidence is incomplete'):
            verify_windows_files(self.root,self.info)


if __name__=='__main__':unittest.main()
