# Frozen CLI measurement results

Measured commit fd6bebebbc1f5f8d5ecbf523822dd396ade10309, CI40420587166,
Windows artifact12696593175. Windows Server2025 build26100, MSVC19.51.36260.0.
Source/vector freeze443d0ea predates evaluation; source and compiler flags unchanged.

| Configuration | PE SHA256 | Code bytes | Listed instructions | Conversion |
|---|---|---:|---:|---|
| O1 | bdb89298a4048d3ab51b207d45f5cd8005c69c744578af2413267db5758860e3 |226|89|Rejected: linker IAT extent/alignment|
| O2 |3615cb6b4a263d0e5fe4c2947a516930c86dea3a75d1d2ae0b1fd4771e243c34|350|130|Rejected: linker IAT extent/alignment|

Both contain .text RX, .rdata R and .reloc discardable/R sections; raw sizes512
bytes each, RVAs1000/2000/3000. Entry1000, preferred base400000. Directories:
imports(40bytes), relocations(16), debug(28), IAT(16). Three imports from KERNEL32:
ReadFile, WriteFile, GetStdHandle. No ExitProcess or CRT import was emitted.
All listings and headers/imports are retained in the artifact. inventory.json
records every listed instruction and mnemonic, including NOP padding; wrapped
byte continuations remain in the full dumpbin text. This is not a reachable-CFG
proof or a production parsing/eligibility decision.

22 original regular-file executions passed exact stdout/stderr/exit expectations.
Two original anonymous-pipe executions emitted415a00ff and then exited11, confirming
the documented closed-pipe EOF limitation. Four original access failures produced
read11/write12 with empty stderr. Eight separately compiled scripted API cases
passed, including actual execution of the frozen algorithm under one-byte partial
writes and1/2/1-byte reads. These are not original-PE OS observations. No new Linux
translation is claimed: both converter attempts rejected without replacing the
output file. Existing production support is untouched.

## Complete dependency findings

O1 uses EBP frame264bytes, saved EBX/ESI/EDI, two register-indirect calls through
ESI loaded from the GetStdHandle IAT slot, and direct IAT ReadFile/WriteFile calls.
O2 uses ESP-relative264byte locals, EBP as an input handle (not a frame pointer),
EBX as a WriteFile function token, register-indirect calls and duplicated epilogues.
Both require imported-function provenance through registers, typed borrowed
handles, simultaneous writable count cells and mutable256byte buffer, register
comparisons/subtraction, byte AL/DL reads/writes and flags, indexed stack addressing,
INC (preserving CF), and near/short conditional backedges. O2 additionally contains
66 90 and multi-byte NOP forms; a NOP memory spelling must not imply a memory read.
No vector/SIMD instructions appeared. There are no compiler helper imports.

The three logical loops are byte transform, partial-write progress and outer
streaming. Their complete state graph and API effects must be designed together.
The outer loop cannot use SUB-537's fixed summation recognizer or the input engine's
acyclic proof. Runtime branch/loop execution with faithful transitions, initialized
byte ownership and constant live storage is the required architecture gate.
Expanding the first IAT diagnostic alone would not establish any of this support.

Recommended next integrated scope: specify one shared streaming IR/state/runtime
contract over these measured dependencies, including API function tokens and owned
mutable count/buffer ranges. Before production implementation, explicitly version
and freeze a pipeline-friendly source that checks GetLastError only on failed
ReadFile and treats ERROR_BROKEN_PIPE as EOF; retain this v1 measurement as history.
Do not retrofit that behavior into translation of v1. Repeat both fixed compiler
configurations for that source revision before fixing implementation scope. One
cohesive feature PR should carry contract, normalized lifting, native I/O and
end-to-end validation, with reviewable commits and medium review. Disk-full,
concurrent interference, consoles/devices and failure-after-partial-output need
explicit domain decisions; these samples do not establish cross-OS equivalence.

## CI anomaly preserved

CI40420587166's CLI/compiler job passed, but the existing authored-corpus job timed
out on case20 after15seconds. Artifact12697548276 preserves the original binary
SHA f5638eca59f9ef5bd1bc9c8e1f3f0d550e19ac43e0b6cf9bdb1e5d74128f255a,
command, environment and launch timing. Spawn took0.0082seconds; after15.0073seconds
the process still polled alive. Captured stdout was the complete expected433230,
stderr empty; it was killed and exited1. This establishes a live-process timeout
after output, not its cause. It is a fifth recorded occurrence, on a different
case from earlier corpus14/importedmax/corpus4/corpus21 failures. No retry, larger
threshold or suppression is added. A subsequent green run cannot explain it.
Final review must retain this unresolved issue and distinguish it from the CLI
measurement. Production/XP7/general-app compatibility remains unproved.
