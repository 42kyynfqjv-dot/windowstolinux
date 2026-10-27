# Frozen independent compiler measurement (SUB-571)

Reuse the existing stateful fold/tabs/escape sources and byte oracles unchanged.
Freeze LLVM20.1.8's official Windows x64 distribution (clang-cl targeting x86),
O1/O2, and the manifest flags before evaluation. Download URL and SHA256 come from
https://api.github.com/repos/llvm/llvm-project/releases/tags/llvmorg-20.1.8 .
The installer is extracted with7-Zip into runner temporary storage; no system
installation, new credentials or security configuration is required.

Record actual clang-cl/link/SDK paths, versions and executable hashes before any
compiler invocation, retain full commands, untouched PE hashes and disassembly.
LLVM uses Apache2.0 with LLVM exceptions; components carry their own notices:
https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/LICENSE.TXT .
This measurement invokes the toolchain; it does not import its implementation or
redistribute LLVM source into the converter. Existing MSVC SDK/linker remain the
Windows build environment; the programs use explicit custom entry and kernel32,
without ordinary CRT startup. This does not establish XP/7/application support.

All original Windows cases precede converter evaluation. Accepted artifacts must
convert on both hosts to identical Rust and match exact stdout/stderr/exit. Rejected
artifacts remain explicit; build failure is separate from conversion rejection.
No source edits, flag tuning or production expansion to fit this experiment.
Timeouts fail and retain the exact program/launch record; no retry is introduced.

Reproduce under the same x86 MSVC SDK/linker environment: extract the hash-checked
LLVM archive, set W2L_CLANG_CL to its bin/clang-cl.exe, run
`python research/cli/llvm/measure.py OUTPUT`, then on Linux run
`python research/cli/llvm/check_native.py OUTPUT` on that exact Windows artifact.
CI's multi-root upload retains OUTPUT under llvm-corpus. See RESULTS.md for
observations, selection limits and the next integrated architecture gate.

SUB-572 adds a separate [production integration contract](INTEGRATION.md).
The historical no-support-expansion measurement above is complete. CI now passes
`--require-translation` to both commands to require all six translations while
retaining the same frozen sources/configuration and the original results.
