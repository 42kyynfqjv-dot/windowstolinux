# Explicit initial FP control policy

The versioned opt-in profile
`w2l-win2022-entry-control-027f-mxcsr-1f80-v1` initializes the canonical owned
context's control word to0x027f and MXCSR to0x1f80. It leaves status, tag,
registers, pointers and opcode unknown. The original FNCLEX executes and
establishes exception knowledge before the first waiting instruction. No Linux
FP register read or assumed host default supplies guest bits.

This policy is grounded in the [retained actual-entry observation](evidence/fp-original-entry-cceed83.json)
and [raw stdout](evidence/fp-original-entry-cceed83.jsonl) for unchanged rcedit
PE SHA256 ce252fb1eddd05c3ea6acd73871995b1badd32446d76c6df07abaf8fa44fd22f.
Existing own-child debugger instrumentation stops before original entry,
requests FLOATING_POINT and EXTENDED_REGISTERS using GetThreadContext and then
terminates the owned child. It preserves the observer's existing explicit INT3
qualification: this is not an uninstrumented baseline. Source SHA and raw hashes
are retained; run41354388017, artifact13102940647 belongs to cceed83.

The captured CW is0x027f, status0, tag0xffff, MXCSR0x1f80 and reported mask0x2ffff.
The policy does not promote that mask into supported features: its declared
SSE/no-DAZ mask remains0xffbf. A single modern-host observation does not prove a
universal Windows loader promise or XP/7 equivalence. Callers must deliberately
select this target profile. Default admission and the previous unknown-state
profile retain their rejection.

Construction requires live initialization and process/thread/fiber ownership,
rejects rebinding an existing context and never overwrites nondefault or pending
exception state. Instruction effects continue to validate lifetime and checked
memory. The context's status remains unknown immediately after construction;
waiting before original FNCLEX must reject. Observation validation retains
nondefault/pending inputs verbatim and rejects missing context categories.

The connected original-entry component now reaches **0x4015da → 0x407158**, after original
precision-helper return, stack cleanup and result checking. The following configuration call stays rejected. The already supported original
RET0 helper at0x401bbc and subsequent PUSH EAX execute; the checked stack carries
its real zero argument. Its former stopped-inner-frame argument
assertions were replaced by checks of the executed MXCSR observation and final
control state because that inner frame has now returned. Other independent
original-call cases still check actual arguments and return/alias/failure rules.

Review also recovered a full disk that prevented sandbox launch. Twenty-two
inactive generated ELF binaries were copied to /tmp/w2l-recovery-3ec2614, verified
by SHA256 and only then removed from their former locations; its manifest allows
restoration. Original PE/source/Windows artifacts and logs remain. The pending
replay's native link bus error is preserved. The exact failed dispatcher test
passed after recovery using /tmp build storage. A separate replay encountered
the new profile test's overly specific expected-error string; that expectation
was corrected to the existing unknown-summary rejection. Neither run is claimed
as a final coherent pass. Fresh replay and CI must establish their own outcomes.

Independent review found no additional runtime defect in the preceding bounded
FWAIT/FNSTCW/FLDCW/STMXCSR effects. Pending delivery and deferred FLDCW unmasking
remain rejected. Full startup/rcedit/default admission, broader exception paths
and historical Windows timeout causes remain unresolved.

Validation before publication: 342 CRT tests pass (two artifact gates handled
separately); the final original-entry canonical gate passes at the new boundary,
and the 152 word cases pass under512KiB with64KiB environment padding. The
Python suite has107 tests with one skip. The prior head3ec2614 has both Rust
workflows green; its inventory and later heads must be checked separately.
No complete replay or final-head CI success is asserted while those are pending.
