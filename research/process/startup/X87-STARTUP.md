# Explicit guest x87 startup state

## New connected boundary

With the additional declared `w2l-modern-enabled-stationary-x87-v1` profile,
the unchanged authored entry executes original **FNCLEX at `0x40158a`**, then
CALL `0x40158c -> 0x401e00`. That helper executes original register saves, equal
constant bounds, comparison, empty-array branch, restoration and RET. No callback
is skipped: the original interval has identical begin/end `0x41b1c0`. Nonempty
helper calls remain rejected. Original PUSH `0x401591` places `0x401e2c` on the
actual stack. Execution rejects **before CALL `0x401596 -> 0x401b0f`**, the next
onexit-registration wrapper. Previous fields, tables, state1/scope0 and the new
x87 effects remain live; no callback return or cleanup is fabricated.

This is connected original-entry component execution under declared profiles,
not ordinary converter admission or unchanged-binary entry-to-exit equivalence.
The existing entry test still supplies its recorded/declared CPU and entropy
context. Full startup/formatter/rcedit/default admission remain unsupported.
There are zero new whole-PE Windows/ELF comparisons.

## Primary contract and knowledge

Intel SDM Vol2A, FCLEX/FNCLEX, pp3-321..322 specifies clearing PE/UE/OE/ZE/DE/IE,
ES, SF and B (status bits0..7 and15). TOP11..13 is preserved. **C0/C1/C2/C3 are
undefined**, not guaranteed preserved or zero. Our state clears known-zero mask
`0x80ff`, preserves only existing TOP knowledge (`0x3800`), and removes condition
code knowledge (`0x4700`). Unknown values never acquire assumed defaults.

Control/tag words, data registers, opcode and instruction/data pointers remain
unchanged; MXCSR is separate and unaffected. The implementation performs integer
state updates and never reads or changes host FPU state. Integer flags and XMM
lanes are preserved by this effect. Native emission requires the consumer's
explicit effect binding; generic emission and pure-fragment transformations
reject the unbound effect. Only exact unprefixed `DB E2` is recognized here.
FCLEX/FWAIT, FNINIT, FLDCW/FNSTCW and other floating operations remain rejected.

FNCLEX is nonwaiting: it clears even a pending unmasked guest exception without
first dispatching it. This is not FCLEX/FWAIT exception suppression. The declared
profile specifies modern user-mode semantics with x87 available/enabled
(CR0.EM=TS=0), excluding the legacy 486/Pentium/Quark DOS-compatible interrupt
window. Those kernel/legacy modes and #NM delivery are not supported or acquired
from Windows. A mismatching/unset profile rejects before the effect; ordinary
runtime construction leaves the profile unset.

## Ownership and lifetime

Guest state belongs to the canonical runtime/process/thread and initialization
epoch, rather than a copied call frame or host thread-local register. Configuration
creates wholly unknown state, not a capture of a Windows or Linux initial FPU.
The first instruction binds the current stationary fiber identity; later fiber
changes or retirement/reuse reject before mutation. This covers only the existing
single stationary guest context, not Windows fiber floating-state switching.
The selected fiber is delayed only while initial state is wholly unknown; no
initial-state acquisition API or authority is issued by that delay.

Expired initialization, storage, foreign process/thread and context rebinding
reject before clearing. CALL/RET and failed callbacks share live runtime state,
so prior FPU effects survive a later unsupported call. Repeating FNCLEX within a
valid activation is architecturally legal and idempotent; replaying a completed
protected return or expired caller remains rejected. No CONTEXT floating-state
capture, exception restoration or new pointer/continuation authority is granted.

## Independent evidence and limits

[Expectations](evidence/x87-expectations.json) were frozen before implementation.
[Primary-source provenance](evidence/x87-primary-sources.json) pins the official
Intel PDF hash. [Results](evidence/x87-startup.json) records source and artifact
hashes, named gates and review limits.

Five named tests cover 262,144 independently checked status/control combinations,
seven partial-knowledge patterns, eleven lifecycle cases and seven emitted-call
modes. Success and failure assertions are explicit. The emitted instruction plus
RET test checks unchanged integer/XMM state, expiry, malformed return and replay.
Four additional original-body array cases cover unknown initial FPU state,
known pending unmasked flags, changed instruction bytes and expired initialization.
Without the new profile the retained component tests still stop before FNCLEX.

The authored native probe performs **42 Linux x86-64 instruction observations**,
seeding masked/unmasked control and status values in an isolated native child.
One assembly block saves host FXSAVE state, loads the declared environment,
observes actual FNCLEX and restores the complete saved state before assertions.
It compares only architecturally defined result bits and preserved state, never
assumes a physical value for undefined condition codes. These are instruction
observations, **not Windows observations or translated PE pairs**.
[Raw observations](evidence/x87-native-linux-observations.txt) list CW, requested
SW, actual seeded SW and resulting SW in hexadecimal.

[Static inventory](evidence/x87-inventory.json) is reproducible with
`python3 research/process/startup/inventory_x87.py PE OUTPUT`. It identifies
floating operations throughout linear executable-section disassembly; it does
not prove their reachability. Later control helpers include FNSTSW/FNCLEX at
`0x40cee9/0x40ceec`, FSTCW/FLDCW at `0x40d00b/0x40d0e9`, and environment/MXCSR
operations elsewhere. They are not admitted by this milestone. The complete
first callback has only the single inline FNCLEX; its remaining calls and future
registered callback still require their own instruction/effect composition.

Next connect original `0x401b0f -> 0x401ae1` registration under canonical onexit
storage, encoded pointer ownership, allocation/failure and return contracts.
The pushed callback `0x401e2c` itself has an equal-bound array at `0x41b1c8`, but
registration must not be replaced with successful execution or a no-op. Sol can
review and inventory this next scope; this completed FNCLEX slice needed no Astra
escalation. Broader frees, error/new-handler, exceptional cleanup/delivery,
collided unwind, native close/EOF and resource/encoding/XP7 equivalence remain
unproven. Historical original-Windows timeout causes remain unresolved.
