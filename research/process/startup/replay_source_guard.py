"""Reject reports assembled while their implementation sources change."""
import hashlib
from pathlib import Path
import subprocess


class ReplaySourceGuard:
    def __init__(self, root, output):
        self.root = Path(root).resolve()
        self.output = Path(output).resolve()
        self.initial = self.snapshot()

    def snapshot(self):
        files = {}
        for name in ('src', 'examples', 'research/process/startup', 'Cargo.toml',
                     'Cargo.lock', 'build.rs', 'rust-toolchain.toml'):
            path = self.root / name
            candidates = path.rglob('*') if path.is_dir() else [path]
            for file in candidates:
                if (not file.is_file() or '__pycache__' in file.parts
                        or file.suffix == '.pyc' or file.resolve().is_relative_to(self.output)):
                    continue
                files[str(file.relative_to(self.root))] = hashlib.sha256(file.read_bytes()).hexdigest()
        def git(*args, input=None):
            result = subprocess.run(['git', '-C', str(self.root), *args],
                                    input=input, capture_output=True, check=False)
            return result.stdout.decode().strip() if result.returncode == 0 else None
        head = git('rev-parse', 'HEAD')
        status = git('status', '--porcelain', '--', 'src', 'examples',
                     'research/process/startup', 'Cargo.toml', 'Cargo.lock',
                     'build.rs', 'rust-toolchain.toml')
        # Status can hide ignored inputs and assume-unchanged worktree edits.
        # Compare every included path and its Git-normalized blob to HEAD too.
        tree = git('ls-tree', '-r', '-z', 'HEAD', '--', 'src', 'examples',
                   'research/process/startup', 'Cargo.toml', 'Cargo.lock',
                   'build.rs', 'rust-toolchain.toml')
        committed = {}
        if tree is not None:
            for entry in tree.split('\0'):
                if not entry:
                    continue
                metadata, name = entry.split('\t', 1)
                mode, kind, oid = metadata.split()
                if '__pycache__' in Path(name).parts or Path(name).suffix == '.pyc':
                    continue
                if mode not in ('100644', '100755') or kind != 'blob':
                    committed = None
                    break
                committed[name] = oid
        matches = bool(head and committed is not None and set(committed) == set(files))
        if matches:
            names = sorted(files)
            if any('\n' in name or '\r' in name or (self.root/name).is_symlink()
                   for name in names):
                matches = False
            else:
                # hash-object applies the same CRLF/attribute normalization as
                # Git without writing objects or changing the index.
                hashes = git('hash-object', '--stdin-paths',
                             input=('\n'.join(names)+'\n').encode())
                matches = hashes is not None and hashes.splitlines() == [committed[n] for n in names]
        return dict(head=head, pinned_commit=head if status == '' and matches else None,
                    committed_source_match=matches,
                    files=dict(sorted(files.items())))

    def verify(self):
        if self.snapshot() != self.initial:
            raise ValueError('replay source changed while running; prior outputs retained')
        return self.initial
