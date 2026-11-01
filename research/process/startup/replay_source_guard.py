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
        def git(*args):
            result = subprocess.run(['git', '-C', str(self.root), *args],
                                    capture_output=True, check=False)
            return result.stdout.decode().strip() if result.returncode == 0 else None
        head = git('rev-parse', 'HEAD')
        status = git('status', '--porcelain', '--', 'src', 'examples',
                     'research/process/startup', 'Cargo.toml', 'Cargo.lock',
                     'build.rs', 'rust-toolchain.toml')
        return dict(head=head, pinned_commit=head if status == '' else None,
                    files=dict(sorted(files.items())))

    def verify(self):
        if self.snapshot() != self.initial:
            raise ValueError('replay source changed while running; prior outputs retained')
        return self.initial
