# Contributing

Start with the [community roadmap](docs/COMMUNITY-ROADMAP.md) and an existing public
issue. Comment to coordinate, fork the repository, create a focused branch and
submit a PR. Maintainers review and merge after the final commit's checks pass.
No repository permission or collaborator change is needed to contribute.

Keep related work cohesive and reviewable. Describe the behavior, supported domain,
error/rejection cases and evidence. Run:

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

Run the relevant documented Python/component checks too. CI performs original
Windows versus generated Linux comparisons; local compilation alone is not that
evidence. For new behavior provide independent expectations and authored or
appropriately licensed fixtures. Preserve original compiler artifacts/hashes,
frozen configurations and exact stdout/stderr/exit results. Report component/model,
scripted backend, Linux-only and genuine differential counts separately.

Use shared instruction/API/memory semantics, never application names, hashes or
answer stencils in production. Keep unsupported paths explicit; don't skip CRT
startup, erase unknown state or relax proof gates to make a fixture pass. Reserve
whole unrelated project/dependency families for held-out validation. Coordinate
unsettled architecture in a design discussion before implementation.

Original code is MIT OR Apache-2.0; record source, license and changes for outside
material. No proprietary fixtures, unreviewed Wine source ports, unsupported
clean-room claims or silent third-party relicensing. Do not include credentials,
user files or large downloaded application binaries in PRs. No driver/kernel,
privileged storage, security-setting, release or deployment operation is part of
a normal contribution. Use temporary authored inputs and bounded non-destructive
checks. Disclose limitations and failed attempts; do not hide timeouts with retries.
