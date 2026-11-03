# Original cleanup and manual restoration composition

The experimental `unwind_slice` compiler validates original authored scope rows,
compiles their bound original cleanup functions and the original authored
`Dispatch` helper, and composes them with private
owned runtime cleanup requests. A completed cleanup creates an internal receipt;
only the matching event/frame/scope/action may advance the cursor. The frame
remains live for writes, and abandoned frames retire only after their last scope.
The selected frame remains live. `Dispatch` instructions perform table target
selection, trace/local copying and parent-cursor writes. Original restore MOV/JMP instructions then
produce the known restored fields at a target-instruction observation boundary.

## Scope and trusted cut

This is an original instruction-slice composition, not recovered rcedit/EH4
metadata or a whole-PE translation. The independently authored Windows program
uses its own table in actual __finally dispatch. Windows SEH chooses scopes;
the compiler receives active scope indices and selected activation at an explicit
orchestration cut. Original registration, Windows SEH selector/dispatcher
instructions and Windows RtlUnwind effects are not yet proved by this slice. The
authored `Dispatch` function is a separate compiled C helper; lifting it does not
close those Windows SEH effects. The Windows manual
restore helper executes separately after the exception is handled; it is not
claimed to be the implementation used by Windows's preceding SEH unwind.

A cleanup receives two exclusive, initialized contiguous words under a protected
helper-call ABI: trace and frame local. The original C dispatch copies the shared
trace into this object and copies it back on return. Native emission follows the
same ordering. Admitted helper operations have no calls, pointer escape, arbitrary
memory, uninitialized read or exceptional effect; intermediate copies have no
external observer in the declared domain. Host/debugger asynchronous effects are
outside it. Memory faults or other unproved cleanup effects reject compilation.
The runtime preserves writes before a detected failure, blocks later effects and
restoration, and never retries or rolls back those effects as though they did not
occur. Its error path alone does not establish Windows exception equivalence.

The restore helper loads EAX, ESP, EBP and target IP from owned selected saved
context. EBX/ESI/EDI remain current values. ECX holds an opaque context pointer;
EDX/flags may be clobbered by admitted cleanup and are returned as None, never
invented numeric state. The target bytes establish an instruction boundary but
are not executed. FS restoration and complete CONTEXT restoration are unproved.
The current and saved contexts are distinct inputs, including when selected is
the innermost frame. A review regression exercises that case with different
nonvolatile snapshots.

## Rejection and acceptance

Checked image arithmetic, disjoint metadata/code regions, full table rows,
known target bindings, bounded acyclic parent chains and unique active scope
ownership precede emission. Unsupported cleanup/restoration instructions,
truncations, protected writes, invalid field offsets, scope cycles/aliases and
unknown targets reject. Reused active table rows across recursive activations
are conservatively rejected in this slice.

The frozen original Windows case expects trace 0x123, inner local 118, outer local
213, selected local 300 and no abandoned fallthrough. A separate original manual
restore observes EAX77 and equal saved/restored ESP and EBP. It does not print
the numeric ESP/EBP values or a complete register vector. Native comparison
uses the unchanged PE/table/helper hashes and these observations; full register
vectors additionally use independently supplied slice snapshots. It contributes
no whole-PE compatibility claim. Record the actual CI outcome before counting
Windows/native evidence; local tests alone are not that evidence.

## Remaining startup gate

Derive active scopes, selected frame and original registration from the original
handler/dispatcher instructions and owned thread/module state. Supply actual
RtlUnwind, nested/collided unwind, notification and failure effects. Bind phase-local
memory to original saved frames, restore FS and any other observable state, and
prove root containment across every admitted path before production eligibility.
PR #45 remains draft until that milestone is substantively accepted.

## Local validation before first publication

The counts in this section describe the initial publication checkpoint, not the
current integrated dispatcher review.

24 unwind example functions passed: ten inherited graph functions, three cleanup,
seven runtime and four composed proof/native integration functions. Independent
byte/metadata vectors gave eight native outcomes, eight deterministic reconversions,
16 input rejections and 19 compiler rejections. Formatting and all-target Clippy
passed. Review fixed selected-innermost current/saved context confusion and the
iced-x86 indirect JMP classification (`Jmp_rm32`, not `UInt32` memory). These
are local results; original Windows evidence remains pending the new workflow.

The preceding 52079bfa push/PR full CI runs 40607191255 and 40607196851 both
completed successfully. Logs show about eleven minutes of bounded LLVM/stateful/
CRLF corpus work, not a diagnosed hang. No runs were cancelled or retried.

First dedicated run 40609222739 at 45ffc7a failed before Windows execution:
retained build.txt reports C2365, because Windows headers expand the authored
variable `exception_code` to a CRT function name. The correction renames only
that variable and records the prior source hash in the freeze history. Expected
results, compiler flags and converter support are unchanged. No execution or
translation evidence is counted from the failed build; no retry masks it.

Entry current EFLAGS obeys `(flags & !0x8d5) == 0x202`, matching the earlier
resume-slice domain. TF/RF and other unmodeled control/debug modes reject before
cleanup; generated-code tests exercise those negatives. Cleanup's resulting
status flags remain unknown in the returned observation, and the saved-context
flags are not restored by the admitted original helper. This precondition closes
an additional unmodeled debug/flag effect; it does not change fixture expectations.

## Retained artifact review and original Dispatch integration

The retained successful original observation has PE SHA256
`55a2435e8800b54f81c20b55373b56206c24bdeeeadc9580bb39b80bf5e04ce5`, source SHA256
`143932ec0de25e0e3269c4d7774d78f411efae331e8aa52dd3c97cae05ecaeb1`, and
object SHA256 `853bd1b85ec5b43e0580ba023848fd1a7a1652f2a91f454079637849f0792404`.
Its recorded baseline is **Windows Server 2022, build 20348**, with MSVC
14.44.35207 and Windows SDK 10.0.26100.0. This is neither XP/7 validation nor a
Windows Server 2025 observation.

The original-Windows timeout in full CI for `23c72898` remains unresolved. The
successful retained unwind artifact is separate evidence and does not explain
that timeout or establish that rerunning fixed it. The updated checker and
original-Dispatch composition have passed local replay against this retained
artifact; fresh CI for these new changes is still required.

`coff_binding.py` reads the retained ordinary x86 COFF symbol, section and
relocation records. It uniquely matches each complete function's nonrelocated
bytes into executable PE bytes, rejects ambiguous matches and checks relocation
targets. Symbol names select research evidence only; production conversion does
not dispatch on an application or symbol name. For this retained artifact:

| Evidence | Bound location or effect |
| --- | --- |
| Original authored `Dispatch` | RVA `0x1060`, 93 bytes including its failure arm |
| Shared trace word | RVA `0x1c948`, unique writable non-executable image range |
| Table target/parent loads | Original operand offsets `0x2c` and `0x47`, both bound to the measured table |
| Original direct calls | Inner RVAs `0x1176`, `0x1187`; Outer RVA `0x122a` |
| Failure arm | Import slot RVA `0x15004`, independently bound to `KERNEL32.dll!ExitProcess` |

The original unsigned compare rejects negative cursors and cursors greater than
2 before table indexing. The supported proof domain admits only validated active
rows. This does not claim that a native error return is equivalent to the
original `ExitProcess(91)` failure arm. Original calls copy a shared trace and
one live frame-local word to a temporary pair, call the selected original cleanup,
copy both words back, then write the original parent row to the live cursor.
Independent expected row transitions are `0→1` with digit 1 and local increment
7, `1→-1` with digit 2/increment 11, and `2→-1` with digit 3/increment 13.

The Linux harness now rebinds retained source and manifest, original stdout and
stderr, the launch's executed PE copy/hash and successful exit, original table,
cleanup/restore bytes and their independent instruction expectations before using
any observation as an oracle. Previously it checked PE/code hashes but trusted
the observation fields in `report.json`; edited report values could therefore
become native expectations. Six focused oracle tests cover that defect. Eight
COFF/PE tests cover instruction tampering, ambiguous matching, truncation,
relocation type/overlap, trace/table identities, direct caller identity and failure
import identity. These tests mutate bytes in memory; they do not execute altered PEs.

The native report separates `windows_observed`, `native_asserted` and
`independent_slice_inputs`. In particular, native ESP `32768`, EBP `33024` and
nonvolatile register snapshots are **test inputs**, not recorded Windows register
values. Active scopes `[-1,2,0]`, selected activation 0 and initial frame values
also remain explicit input assumptions. The native target is an instruction
boundary; its original continuation instructions are not executed. Existing
Windows reports may predate COFF extraction: derivation uses their unchanged
retained object and PE and is recorded in the native report, without rewriting
the original report or claiming a new Windows run.

Reproduce the evidence gates with:

```sh
python research/process/startup/check_unwind.py --self-test
python research/process/startup/check_unwind.py --verify-only ORIGINAL_UNWIND_DIRECTORY
python research/process/startup/coff_binding.py --test-artifact ORIGINAL_UNWIND_DIRECTORY
python research/process/startup/check_unwind.py ORIGINAL_UNWIND_DIRECTORY target/debug/examples/unwind_slice
```

The next original-code gate is the actual finally funclet/activation boundary:
recover and validate the caller-frame addressing at the three original call
sites, including the disjoint `[EBP-0x20]` cursor and `[EBP-0x1c]` local words,
then derive scope activation and selection from original handler/registration
instructions. Tests must cover swapped/aliased frame slots, a stale or retired
frame, changed table target/parent and invalid scope transitions. Caller byte
provenance alone is not proof of those execution effects. Windows SEH selection,
root containment and full startup eligibility remain open; no whole-PE admission
is granted by the successful authored helper composition.
