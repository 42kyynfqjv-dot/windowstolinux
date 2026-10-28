# Original cleanup and manual restoration composition

The experimental `unwind_slice` compiler validates original authored scope rows,
compiles their bound original cleanup functions, and composes them with private
owned runtime cleanup requests. A completed cleanup creates an internal receipt;
only the matching event/frame/scope/action may advance the cursor. The frame
remains live for writes, and abandoned frames retire only after their last scope.
The selected frame remains live. Original restore MOV/JMP instructions then
produce the known restored fields at a target-instruction observation boundary.

## Scope and trusted cut

This is an original instruction-slice composition, not recovered rcedit/EH4
metadata or a whole-PE translation. The independently authored Windows program
uses its own table in actual __finally dispatch. Windows SEH chooses scopes;
the compiler receives active scope indices and selected activation at an explicit
orchestration cut. Original registration, selector/dispatcher instructions and
Windows RtlUnwind effects are not yet proved by this slice. The Windows manual
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
restore observes EAX77 and equal saved/restored ESP and EBP. Native comparison
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
