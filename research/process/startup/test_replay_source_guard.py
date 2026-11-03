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

    def test_hidden_worktree_inputs_cannot_claim_the_commit(self):
        for mode in ('ignored', 'assume-unchanged'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root/'src').mkdir()
                (root/'src/a.rs').write_text('original\n')
                (root/'.gitignore').write_text('src/ignored.rs\n')
                def git(*args):
                    return subprocess.run(['git', '-C', tmp, *args], check=True,
                                          capture_output=True).stdout
                git('init')
                git('add', '.')
                git('-c', 'user.name=Replay Test', '-c', 'user.email=replay@example.invalid',
                    'commit', '-m', 'original')
                if mode == 'ignored':
                    (root/'src/ignored.rs').write_text('extra input')
                else:
                    git('update-index', '--assume-unchanged', 'src/a.rs')
                    (root/'src/a.rs').write_text('hidden edit\n')
                self.assertEqual(git('status', '--porcelain'), b'')
                guard = ReplaySourceGuard(root, root/'evidence')
                self.assertIsNone(guard.initial['pinned_commit'])
                self.assertFalse(guard.initial['committed_source_match'])

    def test_clean_crlf_sources_match_the_normalized_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'src').mkdir()
            (root/'src/a.rs').write_bytes(b'first\nsecond\n')
            def git(*args):
                return subprocess.run(['git', '-C', tmp, *args], check=True,
                                      capture_output=True).stdout
            git('init')
            git('config', 'core.autocrlf', 'true')
            git('add', '.')
            git('-c', 'user.name=Replay Test', '-c', 'user.email=replay@example.invalid',
                'commit', '-m', 'original')
            (root/'src/a.rs').unlink()
            git('checkout', '--', 'src/a.rs')
            self.assertEqual((root/'src/a.rs').read_bytes(), b'first\r\nsecond\r\n')
            self.assertEqual(git('status', '--porcelain'), b'')
            guard = ReplaySourceGuard(root, root/'evidence')
            self.assertTrue(guard.initial['committed_source_match'])
            self.assertEqual(guard.initial['pinned_commit'], guard.initial['head'])
