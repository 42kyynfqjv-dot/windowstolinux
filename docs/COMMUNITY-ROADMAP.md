# Community roadmap

WindowsToLinux aims to mechanically recompile supported Windows application logic
into native Rust/Linux ELF, with independently implemented native support where
needed. It is an early, explicitly bounded project. Selected authored PE32 console
programs have real Windows/ELF comparisons, including streaming and runtime input.
**Unmodified ISCC and rcedit have Windows baselines but do not translate.** Ordinary
CRT startup, general modules/heap/API composition, PE32+, desktop/COM, drivers and
XP/7 compatibility are not established. See [README](../README.md),
[shared architecture](../research/process/DESIGN.md),
[checked-memory boundary](../research/process/IMPLEMENTATION.md) and the
[historical engineering roadmap](../ROADMAP.md).

## Contribution ready

These have stable existing interfaces, bounded deliverables and tests. Comment on
an issue to coordinate; fork and submit a PR. Maintainers review and merge.

| Issue | Deliverable | Required evidence |
| --- | --- | --- |
| [#38: launch diagnostic failures](https://github.com/42kyynfqjv-dot/windowstolinux/issues/38) | Portable tests for diagnostic subprocess failure without losing the primary timeout | Mocked diagnostic failures plus bounded authored children; no retry/threshold changes |
| [#39: read-only provenance validator](https://github.com/42kyynfqjv-dot/windowstolinux/issues/39) | Deterministic checker for one existing evidence format | Synthetic independent malformed/hash/count cases; no executable or network invocation |

Documentation fixes with verified commands/links and independently specified
conformance cases for already-admitted behavior are welcome. Coordinate test
additions around a meaningful gap; large raw case counts are not compatibility.

## Design discussions — interfaces still unsettled

| Issue | Decision needed before implementation |
| --- | --- |
| [#40: Wine failure reproduction](https://github.com/42kyynfqjv-dot/windowstolinux/issues/40) | Same-version Windows/Wine GUI behavior, package/asset provenance and disposable isolation. WinMerge deletion is a reported feature failure, not a verified current failure or unrunnable app. |
| [#41: future device backend](https://github.com/42kyynfqjv-dot/windowstolinux/issues/41) | Handle/device identity, operation/buffer contracts, errors, async/cancellation, privileges and lifetime. Mock-only design; no kernel/hardware operations. |

Shared checked storage is merged under existing proof/admission gates
(SUB-576 / [PR #37](https://github.com/42kyynfqjv-dot/windowstolinux/pull/37)).
Current SUB-577 [draft PR #43](https://github.com/42kyynfqjv-dot/windowstolinux/pull/43)
adds bounded heap effects and conformance; heap PE translation is still blocked.
Process-address composition, module startup and API effects need reviewed contracts
before widening support. Discuss those interfaces instead of building parallel
application-specific loaders. Public issues are the contribution queue; Linear
tracks the cohesive maintainer milestones, not a duplicate of every public issue.

## Long-term backlog — no promised support or dates

- General user-mode startup, module/TLS/exception state and heap/API effects.
- Broader independent project families, architectures, threads and asynchronous I/O.
- Desktop/COM and device interfaces whose observable semantics can be mapped safely.
- Windows-kernel-specific drivers and unsupported hardware as a separate research
  track; an existing Linux interface helps only when its behavior matches.
- Release packaging/performance and any quantitative compatibility claim only after
  representative reproducible evidence. The 99% aspiration is not a measured result.

These are not beginner implementation assignments and do not authorize driver
loading, privileged installers, user-disk tests, security changes or deployments.

## Generality and evidence rules

Freeze source/toolchain/configuration and independent expectations before evaluating
conversion. Keep original compiler outputs untouched. Hold out whole unrelated
project/dependency families; currently VirtualDub and CrystalDiskMark/DiskSpd stay
reserved. Use shared instruction, memory and API contracts; no application-name,
PE-hash, expected-answer stencils or guessed startup bypasses in production.
Hashes are provenance checks in tests, not semantic dispatch keys.

Report original Windows observations, actual PE-to-Rust-to-ELF comparisons,
standalone support/model tests and scripted backends separately. Preserve unsupported
rejections, failures and uncertainty. A successful retry does not explain a timeout;
eight historical original-Windows timeouts remain unexplained. Wine failure claims
need pinned reproduction, not stale ratings or missing Linux ports. A kernel-dependent
failure is not automatically a portable user-mode target.

Original project code is MIT OR Apache-2.0. Third-party source/tests/binaries retain
their own licenses and provenance. Wine/Proton may inform behavior research; do not
port source or call a rewrite clean-room without that process. Review concrete reuse
and distribution obligations before importing it. See [CONTRIBUTING](../CONTRIBUTING.md).
