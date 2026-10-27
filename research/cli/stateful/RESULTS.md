# Stateful composition measurement

Sources, flags and independent expected bytes froze in099ebe9 before converter
measurement. No production source changed. The historical full six-artifact
inventory in INVENTORY.json is from Windows run40448357359 at e317f81;
PE hashes are per-run because linker timestamps can change. Compare the exact
same PE between Windows and Linux, not different CI runs.

| Program | Config | Instructions | Windows result | Converter result |
|---|---|---:|---|---|
| CRLF + ASCII fold | O1 |137|31 observations pass|reject MOVZX at RVA10ad|
| CRLF + ASCII fold | O2 |160|31 observations pass|reject MOVZX at RVA10c5|
| Tab expansion | O1 |118|31 observations pass|proof resource exhaustion / UNKNOWN|
| Tab expansion | O2 |141|31 observations pass|proof resource exhaustion / UNKNOWN|
| Escape/delimiter | O1 |122|31 observations pass|accepted; native comparison required|
| Escape/delimiter | O2 |147|31 observations pass|accepted; native comparison required|

All186 real Windows observations passed:14 inputs through file and pipe plus
three failures per build. All72 separate authored Windows backend records passed.
The C backend harness is ordinary-CRT-linked, includes the unchanged freestanding
source and substitutes APIs; it is not a converter target or original OS scheduling
observation. A local C type-shim check of those72 cases is development evidence only.
Windows Server2025/build26100, MSVC compiler/linker versions and exact commands are
recorded in each artifact's build logs. Sources, flags and all frozen hashes are
unchanged, including the tab-expansion program that currently cannot be proved.

Linux must compare all six exact PE hashes. The two accepted escape programs
require62 actual Windows/ELF output/stderr/exit comparisons with byte-identical
Rust. They also execute24 frozen backend scenarios each (48 native backend runs),
separately compared with Windows C-probe expectations. Four rejected programs
preserve the destination sentinel; fold has exact diagnostic agreement, while
proof-budget rejection classification retains both raw diagnostics and explicitly
records that full text equality is not required. Windows Z3 error strings use
different backslash quoting from Linux; proof limits can also depend on the host.
UNKNOWN is inability to establish the safety contract, not evidence of unsafety.
No rejected artifact contributes an ELF comparison.

## Full inventory and next integrated gate

All builds use the same three linker section families and four supported Win32
imports. Full instruction and permission inventories are retained, not just the
first rejected instruction. Fold's additional forms are two register MOVZX
operations (ECX from AL; EAX from BL/DL), then CMOVA ECX,EAX. A MOVZX-only patch
would still leave conditional selection and resulting byte/flag/proof integration.
Tab expansion already decodes every observed mnemonic. Its column state ranges
0..3, resets on CR/LF and uses AND reg,3; output can grow fourfold. The current
binary-state capacity hint does not supply this weighted expansion invariant.
The two escapes reuse the current implementation without a new recognizer.

Recommended **one cohesive Astra High implementation gate**: normalized unsigned
register zero extension and CF/ZF-based conditional selection, plus reusable
finite-control/weighted input-output loop invariants for initialized output
expansion. Inventory the actual four rejected graphs together. Keep candidate
invariants independently proved, both proof phases mandatory, memory/ownership
checks and existing solver budgets; reject unresolved cases honestly. Do not
infer that decoded tabs are safe or that MOVZX is the sole fold prerequisite.

Acceptance is all four unchanged rejected artifacts producing matching native
results for their124 Windows observations, deterministic Rust and exact artifact
hashes; preserve the escape62 comparisons and existing corpora. Add independent
register/flag/partial-width/column-boundary/expansion-gap/stale-read and false-invariant
negative cases, chunk schedules, partial writes and failure exits. No compiler-flag
or source edits, per-fixture output shortcut, general CRT/memory/API expansion.
If the current proof architecture cannot express the required invariant, return a
specific design decision rather than raising budgets or weakening safety silently.

## Measurement failures and limits

Run40448086420 stopped at the frozen-byte check before evaluation: Windows checkout
changed JSON line endings. LF attributes now preserve the original frozen hashes;
expectations were not rehashed. Run40448357359 supplied the Windows inventory; its
initial Linux harness exposed the platform-specific solver error quoting. The
harness now preserves raw text and reports proof-budget category agreement honestly.
Later CI success does not erase these harness failures or diagnose the six historical
original-Windows launch timeouts. No silent retry or relaxed source hash check.

This selected tiny corpus demonstrates one reused stateful utility and two concrete
capability gaps. It is not ordinary CRT, general-app, PE32+ or XP/7 compatibility.
Finite schedules do not prove all OS scheduling/failure behavior or total termination.
Substantive review is required before merge. Final-commit CI and downloaded artifacts
are recorded in PR30; this file preserves the initial measured inventory provenance.
