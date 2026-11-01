import subprocess
import tempfile
import unittest
from pathlib import Path

from replay_source_guard import ReplaySourceGuard


class ReplaySourceTests(unittest.TestCase):
    def test_changes_reject_without_erasing_evidence(self):
        for mutation in ('rust', 'json', 'new'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root/'src').mkdir()
                (root/'src/a.rs').write_text('original')
                evidence = root/'evidence'
                evidence.mkdir()
                (evidence/'failure.txt').write_text('retained')
                guard = ReplaySourceGuard(root, evidence)
                self.assertEqual(guard.verify(), guard.initial)
                changed = root/('src/a.rs' if mutation == 'rust' else
                                'src/data.json' if mutation == 'json' else 'src/new.rs')
                changed.write_text('changed')
                with self.assertRaisesRegex(ValueError, 'source changed'):
                    guard.verify()
                self.assertEqual((evidence/'failure.txt').read_text(), 'retained')

    def test_only_clean_commit_can_be_pinned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'src').mkdir()
            (root/'src/a.rs').write_text('original')
            def git(*args):
                subprocess.run(['git', '-C', tmp, *args], check=True, capture_output=True)
            git('init')
            git('add', '.')
            git('-c', 'user.name=Replay Test', '-c', 'user.email=replay@example.invalid',
                'commit', '-m', 'original')
            clean = ReplaySourceGuard(root, root/'evidence')
            self.assertEqual(clean.initial['pinned_commit'], clean.initial['head'])
            (root/'src/a.rs').write_text('dirty')
            dirty = ReplaySourceGuard(root, root/'evidence')
            self.assertIsNone(dirty.initial['pinned_commit'])
            self.assertIsNone(dirty.verify()['pinned_commit'])
            git('add', '.')
            git('-c', 'user.name=Replay Test', '-c', 'user.email=replay@example.invalid',
                'commit', '-m', 'changed')
            with self.assertRaisesRegex(ValueError, 'source changed'):
                dirty.verify()
