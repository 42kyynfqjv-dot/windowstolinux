# Main entered from the original startup caller

The controlled native-profile entry now executes the actual CALL at `0x401717`
to Main at `0x401280`. It preserves the already produced argc/argv/envp words,
executes Main's original inline EH4 prolog, initial stores, full original memset,
NULL-name module-handle query, result store and scope activation. It stops
**before Main's CALL `0x401316 → 0x4011a0`**. Outer/Inner, exception delivery, Main
completion and process termination are not executed by this change.

Both empty and three-entry synthetic environment variants must reach that same
frontier from the original entry and all preceding initializers. The independent
Main cases also use an explicit post-initializer cut; those cases alone are not
entry-to-exit or whole-PE evidence. No entry jump, guessed Main, callback success
stub or Machine root substituted for the live Main frame is introduced.

## Actual call and owned frames

The caller requires its live normal frame, scope 0, startup state 2 and the
original three-word argument stack. The five original CALL bytes determine the
target and continuation `0x40171c`. Shared CALL machinery mints a fresh protected
return; no Main return is simulated. Main's previous head is the actual installed
startup normal frame, not an empty chain or an externally supplied Main root.

The existing `frame_proof::prove_frame` derives Main's offsets and saved values.
The separate original epilog shape is checked for predecessor restoration,
guard discard, saved-register order, guard-check target and RET. This supplies a
reservation plan, not proof that the security helper or a Main return executed.
Runtime projections validate the actual cookie, encoded scope, both guard words,
saved values and unique return. The saved-SP, body-guard and discarded guard
occupy distinct words. Parent storage and arguments remain intact.

## Publication before saved-SP initialization

Main's FS store at `0x4012b0` precedes MOV `[EBP-24],ESP` at `0x4012b6`.
The shared helper-prolog binding previously required saved ESP before publishing
its record. Applying that order to this inline prolog would change partial
failure behavior.

The shared normal binding now has a bounded pending stage for this original
call-free instruction interval. Its private FS-publication projection omits the
unwritten field completely: no read, invented pointer or value-based readiness.
Ordinary and suspended storage images reject while the field is pending. Even a
preexisting matching pointer does not complete initialization. No event, capture,
return receipt or exception-containment authority is issued from this projection.

Only the actual later MOV checks its destination/source and stores ESP. After a
successful store, full image validation becomes available. A failed store leaves
the already installed child head and earlier prolog writes intact. A later guard
or cookie validation failure leaves the successful MOV visible as well.

Review caught a premature generic alias check on the pending word. That check
would have rejected an old protected tag before the FS store, erasing the prior
publication effect. Only that exact pending word is deferred to its actual MOV;
other protected aliases still reject. The regression installs the corrupt word
before executing the prolog and checks that publication precedes rejection.

## Stack growth and original body effects

The real prolog uses `ADD ESP, -0x2fc`. Shared lowering now distinguishes a negative
immediate from positive cdecl argument cleanup. Pointer arithmetic and x86 flags
execute normally; growth neither reads, discards nor initializes the newly exposed
bytes. Positive cleanup retains its bounds and protected-word checks. Dynamic
ESP cleanup remains unsupported. This is owned committed guest-stack movement,
not Windows stack-growth or guard-page exception emulation.

The actual full memset at `0x402370` is reused. Its original operands identify
716 ordinary bytes, checked against the instruction-derived frame; the guards,
record and saved slots lie outside that range. The original caller cleans its
arguments and performs the remaining local stores. No zeroed locals are supplied
before the real stores execute.

The NULL-name `GetModuleHandleW` ABI is shared with the existing image query.
The original IAT/name binding is checked. Main obtains the canonical process-owned
image view, validates it, executes the stdcall cleanup and stores that same typed
root. It neither creates a temporary library owner nor increments a reference.
The successful API conservatively invalidates volatile/LastError knowledge.
Named queries and missing or stale authority are not guessed into success.

The original final store transitions Main's try level from -2 to 0. Outer's call
is still unsupported, so no event or normal return follows. Reaching this point
is evidence of entering Main and executing this prefix only.

## Review and validation

Independent review of `c88615b` found no additional getter/fallback, payload
transport or failure-ordering defect. All 569 predecessor replay-source blobs,
report/Rust hashes and its zero whole-PE count were reverified. All three exact
predecessor workflows `41402603270`, `41402596175` and `41402596394` passed.

Twenty-five native Main cases exercise actual call/parent identity, two stack
placements, staged initialization, old matching values, preexisting protected
aliases, wrong operands, duplicate stages, cookie/guard corruption, stale code,
phase/argument-stack rejection, mutation, memset failure and prior effects on
scope-transition failure. Six shared module-API cases check ABI, ownership and
preflight effects. Four independent signed-stack cases distinguish allocation
from cleanup at the unchanged low-stack limit. Epilog mutations and selected
prolog mutations must reject their instruction proof.

The live-entry cases check two installed normal frames, Main's fresh return,
parent-head identity, unchanged argc/argv/envp, original saved-SP/guard words,
716 written zero bytes, module-root identity, active scope 0 and absence of a new
pending exception. All existing canonical, aggregate, Python, Clippy and 152
low-stack cases remain required, followed by a clean final commit-pinned replay.
Read the tracker and replay metadata for final validation/CI outcomes.

Local checks passed before publication: 365 CRT tests (two separately gated
ignores), 185 unwind tests, 182 root tests, the canonical live-entry gate,
115 Python tests (one skip), all-target Clippy with warnings denied and
formatting. All 152 word/register cases also passed with the unchanged 512 KiB
child stack and 64 KiB padding. These local results do not substitute for the
final clean committed-source replay or exact-head CI conclusions.

## Remaining contracts

This is the Main-only checkpoint. The subsequent bounded Outer prefix and
explicit absence representation are recorded in [OUTER-ENTRY.md](OUTER-ENTRY.md).

The next connected scope is original Outer `0x4011a0`, its call to Inner `0x4010c0` and actual
software-exception acquisition. Bind them to this live Main record and suspended
caller with existing shared machinery; do not promote fixture-supplied Machine
or capture state into acquisition authority. Full startup/default/rcedit admission,
Main/CRT return and exit, non-NULL callback validation, concurrent execution,
exceptional delivery/cleanup and resource-failure equivalence remain unproved.

The authored source identifies the first callee as Outer, not Inner. Outer's
actual prolog publishes its record at `0x4011ca` without any saved-ESP store;
its finally-only scope header is `[-2, 0, -48, 0]`. The current shared normal
layout requires a saved-SP word, so reusing Main's delayed-store stage would
invent an eventual store that is absent here. The next bounded integration
must represent instruction-proved absence without issuing restoration authority
from an uninitialized slot. Outer initializes locals 200/2 and scope 0, then
calls Inner at `0x4011e5 → 0x4010c0`. Inner's original RaiseException call is
`0x401117`. These are three distinct execution boundaries, not one acquisition.

Historical original Windows C01 and case-26 timeouts remain separate unresolved
failures before conversion. Their retained owned-process/WCT records have no
stalled IP or stack, and those processes were killed. Passing later runs do not
locate the stall or establish its cause. No timeout, comparison or retained
failure is removed. Synthetic environment data only.
