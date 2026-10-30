# Original FILE scope and the remaining formatter effects

This is a connected component boundary in SUB-579 / PR #45. It adds no complete
startup, formatter or rcedit admission. The formatter driver remains an explicit
cut supplied by the native component harness. Runtime rejection of that cut is
not a replacement for guest exception delivery or termination.

## Instruction-derived work

`FileScopeProof` checks the complete original normal wrapper suffix, lock and
unlock leaves, normal cleanup entry and EH4 epilog. It derives the result local
and checks that it lies inside allocated locals, outside saved registers, guard
and registration metadata. The critical-section member is the checked FILE's
offset 32. Import identities are separate prerequisites; the evidence checker
verifies the original IAT entries are `KERNEL32!EnterCriticalSection` and
`KERNEL32!LeaveCriticalSection`. There is no application-name/hash dispatch.

The emitted sequence uses the existing arithmetic/operand emitter and shared
protected CALL/RET machinery. The latter now has a lock-independent activation
primitive: acquiring a lock cannot require a fictional preexisting lease.
Existing stream calls still check their lease before delegating to it.

After the actual prolog has installed its record in `NormalCallEpoch`, the
wrapper executes the original result initialization, lock, state-zero activation,
driver CALL, result preservation, state -2 store, normal cleanup CALL, result
reload and checked epilog. Lock/unlock leaves execute their original instructions;
only their validated import effects use the owned runtime lock contract. Recursive
acquisition releases its own depth, retaining any outer lease. A void API return
does not manufacture known EAX/ECX/EDX or arithmetic flags.

The component domain requires an initialized, exclusively owned, uncontended
critical section on the current thread, with live storage and bounded recursion.
It does not cover Windows deadlock exceptions, contention, abandoned owners,
asynchronous delivery or startup construction of the original lock object.
These are premises of the component, not conclusions from successful samples.

The driver cut receives the real child activation and held lease. It must execute
its protected RET and preserve the lock stack, active scope, saved values and
registration. Unknown effects fail closed and retain reached storage/CPU effects.
No host RAII destructor releases the lock on an error. Neither scope reset nor
normal epilog runs after an unresolved body error. The unwind entry that first
reloads ESI from the frame is explicitly outside this normal-entry certificate.

## Independent cases and provenance

Three new Rust test functions cover:

- Five independent return values (0, 1, 93, signed minimum bits and all-one bits),
  original instruction execution, a recursive outer lease, scope/result-local
  state at the call, an externally visible body write and exact stack retirement.
- Eight invalid compositions: mismatched lock/cleanup arguments, uninitialized
  lock, unresolved body effect after a write, body changing scope state, body
  releasing the lock, success without the protected RET, an extra live recursive lease, and a cleanup
  argument changed after acquisition. The latter two assert the distinct active
  versus reset scope states and saved-word retention at failure. Failure must preserve
  reached effects and poison the registry without fabricated cleanup.
- Seventeen byte/shape negatives for scope/result ownership, call targets,
  partial/changed operations, lock member, truncation, argument cleanup and an
  unwind entry substituted for normal cleanup.

The normal-wrapper evidence job extracts these new regions from the unchanged
current-run PE and checks its import names. Both hosts execute the three native
test functions using those bytes. **These are native component tests with a
supplied driver, not additional original-Windows differential pairs.** The five
preexisting observer-versus-native helper/epilog comparisons remain separately
reported, with identical PE and emitted-Rust hashes required across hosts.
Zero new whole-PE comparisons are claimed.

## Precise remaining exception/termination contract

The retained authored image establishes these dependencies, independently of
whether its ordinary printf call happened to fail:

1. The FILE wrapper activates EH4 state zero at `0x404677`, calls the formatter
   driver at `0x40467e`, then normally resets state and calls cleanup. Its EH4
   unwind entry is `0x4046a8`, while the normal cleanup call targets `0x4046ab`.
   They cannot be interchanged: the unwind entry additionally restores ESI.
2. Driver `0x4052ba` constructs formatter state, calls the parser, destroys its
   buffer and restores temporary buffering. The existing individual graph proofs
   do not yet compose all those calls under a live C++ registration.
3. The integer dispatcher uses C++ FuncInfo, not EH4. Its state-zero unwind map
   names `0x4026fc`, which jumps to `0x40770c`. This is a termination dependency,
   not the FILE unlock action. Relabeling C++ state zero as EH4's inactive -2
   would erase an observable control-flow effect.
4. `0x40770c` calls the PTD getter `0x40a2e1`, reads the callback at +12 and may
   call that callback after a separate validation call. The getter itself calls
   `0x40a332` and branches directly to `0x4077ff` on a null result. A nonnull PTD
   or null callback alone therefore does not prove ordinary return.
5. `0x4077ff` has signal/reporting dependencies, a conditional `INT 29h` path and
   a call to `0x407004` with status 3. That helper passes cleanup mode 2 to the
   shared exit path. Substituting normal shutdown/flush, dropping a callback, or
   returning a synthetic formatting error is not justified by current evidence.

The next connected gate is the driver/parser/integer activation composition:
bind initialized formatter/context/varargs and the current thread's PTD, prove
all reachable calls and fault conditions for the bounded format grammar, and
either discharge a complete no-escape certificate or execute the original C++
dispatch/termination effects. A selected happy-path trace, a formatting result,
or the normal FILE scope certificate cannot supply that certificate. The smallest
required exceptional cases distinguish failure before lock acquisition, a body
escape with the FILE scope active, C++ state-zero unwind into termination, a PTD
getter failure, and a returning/failing registered termination callback. Until
those effects are closed, full conversion must reject before emission.

Primary contracts: [EnterCriticalSection](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-entercriticalsection),
[LeaveCriticalSection](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-leavecriticalsection),
[terminate](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/terminate-crt?view=msvc-170),
[internal CRT functions](https://learn.microsoft.com/en-us/cpp/c-runtime-library/internal-crt-globals-and-functions?view=msvc-170),
and the original byte/metadata evidence in `formatter_binding.py`. Independent
Rust implementation; no Wine or proprietary source import and no clean-room claim.

## Sol review and connected exception-session gate

Substantive review found no confirmed production defect in this bounded normal
scope. Two additional negative compositions now cover a nested live lease and a
cleanup argument changed after acquisition. They check retained saved words and
different failure points: the former stops with scope zero and two locks; the
latter reaches original cleanup with scope -2 and keeps its lock. Positive cases
also execute an actual nested native activation through distinct protected return
identities. Existing canonical LF vector coverage remains intact.

The concrete remaining integration constraint is in the shared registry, rather
than missing lock instructions. `with_normal_calls` leases the registry under a
finished event and requires the original Machine phase/context to remain fixed.
`expected_callback` explicitly rejects while `normal_epoch` exists. Ordinary CRT
CALLs have a checked normal RET or an unsupported-domain error; that error is not
an owned guest exception. The C++ registration is separately rejected by the EH4
registration validator. Removing any of these guards cannot establish delivery.

The next coherent implementation needs an owned nested exception session which:

1. Suspends a specific live normal activation/epoch without consuming its saved
   predecessor, original event authority or protected returns; derives the new
   event from actual instruction/API state and preserves unknown register bits.
2. Registers the integer function's original C++ record/FuncInfo under its own
   layout/state and invokes proved original dispatch effects. Retains the outer
   EH4 record, actual FILE lease and frame bytes throughout delivery.
3. Distinguishes normal return, nonlocal transfer, termination and unsupported
   effects. Ordered unwind executes only cleanup instructions actually reached.
   C++ termination cannot be turned into an ordinary return or an invented
   release of the outer FILE lock.
4. Restores or abandons the suspended activation using existing owned context
   and cleanup receipts. Requires independent resume, selected-unwind,
   termination-callback return/failure, stale session, wrong thread, nested
   failure and missing-containment negatives before enabling emission.

This is a bounded state/authority and proof/emitter integration decision suitable
for Astra High. Sol can complete review, regression evidence and CI. It is not
permission to admit the full driver while C++ dispatch/PTD/termination remains
unproved, or to infer absence of exceptions from the normal observations.

## Prior checkpoint and failure evidence

For `6cb18d40133e17602d3b97b635564ac697bb420c`, dedicated CI 40694121946 and
full CI 40694121953 succeeded. The dedicated artifact records five comparisons
per host, PE SHA-256 `1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`
and matching Rust SHA-256 `4759c444163bec70791d3b7ec5d77e7476f5c216e1ac92dc4597c15c321a7fea`.
This confirms the CRLF vector fix under fresh Windows/Linux CI.

Parallel full run 40694131051 failed the original-Windows `untaken` imported-output
fixture after 15 seconds. Artifact 12818461816 preserves the exact executable,
empty outputs, launch record and process observation: 0 CPU seconds, loaded CRT,
one observed thread, no detected wait-chain cycle. The measured PE hash is
`b5a3bb8ee10c6ca16d5b9b2b53e39bc214d6fc4a6e6977a1fdf20a7dc7675554`.
These observations do not establish a loader, runner or application cause. The
failure remains unresolved; a concurrent pass is not a fix. No retry, raised
timeout or removed check hides it. Historical timeout evidence remains separate.

## Owned issuance while a normal call is active

The shared native runtime now has a bounded pending software-exception transition.
`CrtNormalException::issue` validates the actual live EH4 frame/epoch, module call
boundary, initialized four-word RaiseException argument area, stack ownership,
and fresh protected CALL slot before publishing suspension. Its initial domain
has no exception parameters and admits only flags 0 or 1. It rejects a reserved
code bit, unknown values, unsupported parameters and invalid continuation lengths.
A separately proved original import binding remains mandatory before this hook
can be used by a production compiler; numeric module membership alone is not one.

Issuance performs the original CALL push and retains the guest call register/flag
snapshot in a non-Clone owned token. The snapshot is not a Windows-captured
CONTEXT. Prior writes, locks, active scope and selected outer event are retained.
The normal registry's state/epilog operations reject while this event is pending,
and normal epoch completion explicitly rejects an unconsumed pending event.
Validation binds the token to its exact arena/thread/epoch/live source frame and
unique continuation slot. There is no Boolean successful-return substitute and
no implicit unlock, argument cleanup, register clobber or host exception recovery.

Two new native test functions exercise continuable/noncontinuable issuance,
unknown versus known flag preservation, foreign-arena and replay rejection, and
ten invalid argument/continuation/stack/IAT cases. Negatives check no issue effects;
positive issuance checks retained writes/locks/protected frame and blocked epilog.
These are component transitions, not original-Windows exception comparisons.
The existing five original-boundary differential cases still exercise normal
helper/epilog restoration and do not validate this newly pending delivery state.

This closes issuance/suspension ownership only. No handler-selection, C++
registration, captured-context restoration or termination outcome is minted.
The pending token deliberately has no resume method until an instruction-derived
containment/dispatch result can authorize that transition. Connecting the owned
handler machine to the suspended normal-frame chain and the original formatter's
C++ FuncInfo remains the next integration gate; full startup remains rejected.


## Exact indirect-call certificate and review of suspension

The suspension hook now consumes a `NormalRaiseCallProof`-emitted site instead
of raw instruction/continuation integers. The proof checks all six original
`FF 15 imm32` bytes, exact bound IAT displacement, checked instruction/IAT
extents, alignment and code/IAT separation. The runtime additionally requires
the full IAT word within a bound module range before publishing any CALL effect.
This reuses the existing explicit import-identity boundary: the enclosing image
proof must still establish that this IAT cell denotes RaiseException. The new
certificate alone does not establish a DLL export, loader resolution or dispatch.
The native suspension tests now consume the emitted certificate, with ten
rejected argument/continuation/stack/IAT cases and an independent compile-time
byte/truncation/prefix/overflow/alias mutation test. No Windows exception delivery
or whole-program comparison has been added.

Review of 64f8a765 found no confirmed loss of the interrupted call's typed
registers, flags, locks or prior writes. Local verification of the connected
certificate change: 175 root, 171 frame and 92 CRT tests pass (one artifact-only
CRT observation test ignored by the ordinary suite); formatting and Clippy pass.
Counts are inherited suite totals, not new independent Windows comparisons.

The full PR run 40705066650 failed original-Windows launch diagnosis: sample13,
`max`, fresh repetition1, PE SHA256
`0610c518a55c36259f91be3c1d2f7c9f8eca153dcfb1970f42e6bdee53f0fe0b`.
The program produced the expected 64 ASCII A bytes with empty stderr, but remained
alive after 15 seconds and was killed. Artifact12823276868 retains the executable,
launch record and process snapshot. The parallel push run's corresponding job
passed. This is unresolved; neither an output match nor a parallel pass explains
failure to terminate. No retry or timeout relaxation was introduced.

The next connected implementation needs an image-bound API effect plus a handler
result that can authorize retirement/restoration of this pending CALL. Existing
OwnedExceptionEvent uses owned FrameId, while this source uses NormalFrameId in
a leased normal epoch; bypassing that identity distinction or reconstructing a
Windows CONTEXT from these guest CALL registers is invalid. C++ FuncInfo dispatch
for the original formatter remains a separate unresolved part of that composition.


## Suspended source validation before dispatch

The pending event now provides a read-only `dispatch_source` projection of the
actual interrupted EH4 frame. It checks the live pending identity, thread-head
capability, exact source binding, typed registers, flag knowledge, CALL stack
position, unique protected continuation, and untouched epilog cursor. The same
storage reconstruction and protected-frame comparison used by normal execution
then revalidate cookies, encoded scope, saved words and registration metadata.
Normal execution still requires the unsuspended epoch: no pending bit is cleared
or temporarily hidden to obtain this projection. No frame storage, lock, guest
register or saved outer event is mutated by successful or rejected projection.

The existing two native issuance functions now also exercise the connected source
projection. Independent mutations cover changed register/flag knowledge, cookie,
encoded scope, saved register word, lost CALL tag and partial epilog cursor. These
checks run for both exception flags0/1; they are component tests and add no Windows
exception or full-PE comparisons. Local175root/171frame/92CRT tests and Clippy pass.

This supplies validated input for dispatch; it does not invent a handler outcome.
A complete bridge must represent a new event whose source is NormalFrameId while
preserving the finished outer Machine event and its context. Existing owned-event
handler transitions assume FrameId registrations, and the leased normal epoch
prohibits those callbacks. Simply clearing suspension or coercing the IDs would
remove the required ownership distinction. The next coherent change needs an
explicit nested-event source/lifetime and handler-result receipt tied to that
source, followed by original cleanup/restoration; formatter C++ FuncInfo remains
unproved. Full startup and rcedit remain rejected.

### Additional timeout investigation

The max failure in40705066650 is a retained process wait, not output-pipe drain:
`corpus/launch.py` sends output directly to files and times `Popen.wait`. Its
observer validated the same live PID/creation time,0.015625CPU seconds, loaded CRT
and one WCT thread with no detected cycle. Those observations establish a live
original process at timeout; they do not identify the Windows wait or root cause.
A separate local real-child regression writes all64expected bytes, stays alive,
and verifies matching output still raises TimeoutExpired, preserves diagnostics
and kills/reaps the owned child. The two launch tests pass; this reproduces the
harness boundary, not the Windows program's underlying hang.

For74649b09, dedicated40707782515 passed; push40707782489 instead failed original
Windows corpus case23 (PE SHA256
`6c4846a95a41aecc55d122576c091538094902940315a7463aff56b707949ab5`),
also at `process.wait` after15seconds. The PR run's authored-Windows job passed.
This is a distinct preserved failure, not a successful reproduction of the max
cause. No retry, relaxed timeout or substitution of translated output was used.

## Owned handler activation on the suspended source

A pending event can now execute one separately bound native callback through the
shared protected CALL/RET implementation. The dispatcher activation is a distinct
CPU; its typed stack and four initialized arguments must fit below the interrupted
CALL, within the same checked stack allocation and outside module ranges. Unknown
or protected argument words, overlapping scratch and reused delivery phases reject.
The body and arguments remain explicit component inputs requiring original-code
and dispatch-effect proof; no captured Windows CONTEXT is synthesized here.

The delivery phases are Pending, Calling, Returned and Failed. A successful exact
RET must preserve callee-saved state; afterward the actual suspended frame is
revalidated and its scope level must be unchanged. Only then is a non-Clone
handler-return receipt issued, bound to registry, epoch, frame and event generation.
This receipt records the actual callback result; it is not a disposition or
permission to resume the interrupted CALL. That call remains suspended, with
its registers/flags and outer event context unchanged. The callback's ordinary
memory writes are retained, including on failure. A failed body, missing RET,
changed saved state or corrupted source poisons the registry and delivery rather
than rolling back writes or clearing suspension.

One native regression function covers seven independently specified executions:
valid result/receipt and replay rejection; body failure after a write; invalid
callee-saved restoration; source metadata corruption; scratch overlap; missing
RET; partially initialized arguments. These are native component tests, not new
Windows handler comparisons. Local suites pass:175root,171frame,93CRT (one
artifact-only observation ignored), formatting and Clippy. Existing recorded
original helper/epilog comparisons remain a separate evidence category.

Remaining composition is substantive: original handler instruction binding and
its actual exception/context arguments, result interpretation/containment, and
source-bound cleanup or guest resumption. In particular, an ordinary callback RET
does not prove that Windows would continue the software RaiseException call.
The enclosing compiler still rejects absent that proof; full startup/rcedit and
formatter C++ FuncInfo remain unsupported. The historical max and corpus23
Windows timeouts remain unexplained, with artifacts retained.

## Consuming callback results without authorizing resumption

Review of e0b1fcd7 found no reproduced violation of protected callback return or
interrupted-state preservation. The next result boundary now consumes the
non-Clone callback receipt only for the same live Returned event, registry,
epoch, source frame and generation, revalidating actual suspended storage again.
Only a fully known scalar may be read as the returned result; pointer addresses
and partially known bits cannot become an exception disposition by numeric cast.
Successful consumption changes delivery to ResultTaken, while the normal epoch
remains suspended. Failure poisons delivery and the registry without erasing
prior callback effects. No method yet interprets that scalar as a Windows
EXCEPTION_DISPOSITION or permits cleanup/guest resumption.

The existing native regression function now executes14component scenarios:
the prior7callback cases plus wrong generation, epoch, owner and frame; partial
scalar and pointer results; changed source storage at consumption. Valid
consumption also tests a fabricated duplicate receipt rejecting in ResultTaken.
Suite totals remain175root/171frame/93CRT; these are not14newWindows comparisons.
Formatting/Clippy pass. This closes result identity and knowledge validation,
not original handler instruction/effect binding.

The precise next original-code bridge involves handler_checks::PrefixProof:
its ValidateContext call consumes the exception's Context pointer and requires
zero incoming exception-record flags. NormalRaiseCallProof proves guest CALL
state, not those captured-context bytes or exception-record flags. Arguments
currently supplied to execute_handler are explicit component inputs. A complete
composition must provide separately owned, initialized exception/context objects
whose observable predicates satisfy the original helper proof, then execute the
original prefix/selection/cleanup with those objects. It must retain unknown
capture bits and model noncontinuable, nested and unwind outcomes; treating
RaiseException argument flags as ExceptionRecord flags or copying guest CALL
registers into captured CONTEXT would invent semantics. This is the bounded
complex contract still needed before original-handler admission or restoration.

The e0b1fcd7 push run40711469487 failed original imported-output `hello` at
process.wait after15seconds, PE hash
`30a0afa2dba23697256b96df129e62a9cc7c099edf68bfcb87eaf125fc3757e3`.
Artifact12826063820 is retained. Dedicated/full PR results are tracked separately;
no retry or timeout change turns this unresolved failure into a success claim.

## Exception/context object binding

`CrtNormalObjects` connects supplied captured-state objects to the pending event.
It requires distinct checked Context-role ranges for an x86 EXCEPTION_RECORD
(80bytes) and CONTEXT(716bytes), aligned addresses, exact live arena/thread/epoch
and event identity. The zero-parameter record must match event code/continuability,
null nested record and zero parameter count. Only fields read by this contract
are required initialized; untouched context registers are not zero-filled.
Captured ESP at0xc4 is a separate initialized input within the registered stack
bounds, not copied from the guest CALL snapshot. Primary layout contracts are
Microsoft x86 CONTEXT and EXCEPTION_RECORD (winnt/ns-winnt-context-r2 and
winnt/ns-winnt-exception_record); delivery acquisition remains an explicit cut.

`execute_bound_handler` requires the actual first three callback arguments to
point to this record, the live source registration and this context. The fourth
argument and original callback code remain separately proved inputs. It executes
the existing protected callback and rechecks object contents/lifetime afterward
before releasing the receipt. This bounded component rejects changes to captured
ESP or record identity fields; it does not claim general context mutation support.
The existing receipt-consumption checks still apply. No captured CONTEXT, OS
exception delivery, original handler selection or guest restoration is invented.

One new native regression function has six independently specified cases:
valid captured ESP unequal to CALL ESP with other context fields unknown;
uninitialized captured ESP; out-of-stack ESP; overlapping objects; substituted
callback object pointer; and captured ESP changed by the callback. Local tests:
175root/171frame/94CRT pass (one artifact-only observation separately replayed),
formatting and Clippy pass. The retained five original helper/epilog comparisons
remain separate from these component cases. No new Windows exception/fullPE pairs.

The next connected scope is original handler prefix/helper execution over these
owned objects, including its selector/exception flags contract, followed by proven
selection and cleanup/restoration. Acquisition of captured-state inputs and
nonzero exception/unwind paths still need proof. Full startup/rcedit remains
rejected; callback completion cannot bypass those gates.

## Independent host exit controls

The mandatory18original Windows launch samples are retained. Before them, the
same harness now runs two independent host-Python controls: os.write of Hello
followed by normal runtime exit, or immediate os._exit(0). Both use unchanged15s
limits, file output and retained process diagnostics; no retry occurs. Controls
have their own report and are mandatory independently of fixture outcomes.
Interpreter binary hash/version are recorded by the harness. They are host
runtime controls (typically64bit), not the fixtures'32bit CRT, and cannot prove
fixture cleanup correctness. Both local Linux controls pass; fresh Windows
results require CI. A passing control alongside a fixture timeout would narrow
that observation but would not establish a root cause. All earlier timeout
artifacts and output-present/process-alive findings remain unresolved.

## Original context-helper composition review

The decoded ContextCheckProof can now emit a checked handler-entry wrapper over
CrtNormalObjects. It validates the event's objects, reads the live initialized
selector from the bound module cell, and runs the original decoded selector/stack
bounds decision against captured ESP before invoking the owned callback. Unknown
selector state rejects before callback effects. Invalid capture still rejects even
if the selector would bypass the original comparison, as required by the declared
valid-stack subset. Other context fields remain unknown.

The composition harness uses literal original helper bytes and includes seven
captured-object scenarios (one added unknown-selector path); it does not replace
the remaining handler body with a proof. CRT suite100passing includes six inherited
context-helper test functions now also compiled into this example: these are
reused coverage, not six new independent tests. Root175/frame171 remain unchanged.
The shortest entry-to-exit route and observable gates are in ENTRY-TO-EXIT.md.

Artifact12828416598 from b245fdf8 PR run40715398388 records both host exit controls
and all18original launch samples passing. This confirms diagnostic wiring, not a
root cause or fix for prior intermittent timeouts. Historical artifacts remain
preserved; no retries, timeout changes or failing samples removed.

Sol review of9c96396a reproduced the projection-versus-live-byte storage gap
outlined in ENTRY-TO-EXIT.md. The new Linux architecture probe records two native
cases and zero translation pairs; it protects against assuming FrameMemory
writes already reach a suspended CRT frame. Existing14normal component tests
passed (one artifact-only observation ignored). No production support expanded.

### Pending-delivery live storage and cleanup composition

The live pending-event harness now connects checked captured-object entry,
original scope-store instruction lowering and the existing original FILE cleanup
graph to the same CRT storage. It verifies read-back before callback completion,
three-level helper calls, protected returns, cleanup lock effects and preservation
of earlier stores on failure. Handler completion remains distinct from nonlocal
restoration. The normal epoch stays suspended, and the finished outer Machine's
saved context is unchanged. Twenty-four native cases plus two retained projection
counterexamples are component evidence; they add no Windows/ELF whole-PE pairs.

The first implementation's adversarial scratch-alias case failed: it allowed a
nested helper stack at the interrupted CALL area. The checked implementation now
requires the current handler activation identity and a stack no higher than its
own entry, in the same checked stack capability. The regression remains mandatory.
Historical original-Windows hangs remain unresolved.

Sol review extended live-adapter regressions to 27 cases: foreign callback identity, cross-arena same-address pointer and scalar establisher bits all reject. Earlier 24-case CI reports remain historical evidence. No production admission changed.
