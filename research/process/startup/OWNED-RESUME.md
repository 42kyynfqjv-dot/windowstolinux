# Composed owned event and original continuation slice

This PR checkpoint composes the shared activation storage with the original
handler compiler and a MOV-only original continuation compiler. It does not
change whole-image admission or admit rcedit/ordinary CRT startup.

## What is proved and emitted

`handler::prove_event` verifies the originating UD2 bytes, disjoint checked code
ranges, the derived next instruction address, a contained raw-disposition-zero
handler, and a closed continuation ending at a RET observation boundary. There
is no runtime caller-supplied continuation or handled Boolean. The emitted wrapper
captures a complete integer state in a live activation, obtains a private event
ticket, executes the original handler operations, commits the edited context,
and executes original continuation MOVs. The ticket binds stack owner, event
generation, live activation and immutable original context. Restoration checks
complete state, original ESP/EBP/EFLAGS and the proof-derived continuation before
changing phase; failed checks leave pending state and frames intact.

ContinueExecution neither selects unwind nor executes cleanup. All activations
remain live. The existing unwind/cleanup lifecycle API does not authorize this
resume path. Original cleanup-body execution and nonlocal selected-handler
restoration remain separate, incomplete production gates.

## Explicit slice premises and observation cut

The input flags must satisfy `(EFLAGS & !0x8d5) == 0x202`: only arithmetic
status bits vary. TF/RF/VM/NT/IOPL/DF and other modes are outside this cut. This
prevents unmodeled debug traps and RF-clearing effects after continuation MOVs.
Independent compiled negatives exercise TF/RF and other excluded mode bits. The
Windows actual fault flags are not claimed equal to the literal snapshot flags.

The input is a complete integer context at the decoded event, with a valid guest
stack and raw-handler ABI. This harness does not prove original FS registration,
thread/module startup, an arbitrary CONTEXT pointer's lifetime, incoming loader
handler opacity, asynchronous exception behavior or a whole application's effect
closure. The native generated entry starts at the UD2 semantic event; it does not
raise a Linux signal. It stops BEFORE the original RET: IP points at RET, ESP is
unchanged, and no guest return address is popped or executed. Native function
return transports an observation to the harness, not a translated x86 RET.

`event_probe.c` is a separately frozen v2 authored Windows experiment. The prior
`slice_probe.c` and its freeze remain unchanged. Windows executes the real UD2,
handler restoration, MOV EDX,EAX and RET, observing EAX/EDX 42. A separate literal
CONTEXT invocation observes the handler's ten integer-field effects. Linux uses
the same retained PE, extracts both original instruction regions, validates hashes
and backing, and observes the emitted event/handler/restored continuation up to
RET. The resulting comparison combines original Windows EAX/EDX observations
with the independent literal-context expectations; it is not a whole-PE execution
pair or an observation of Windows's complete post-RET stack state.

## Independent tests and evidence accounting

The handler example suite has 22 functions: the prior 12 (including ten shared
graph tests), five owned-event identity/phase/atomicity tests, three continuation
proof tests and two composed event proof/native-emission tests. The second
example imports this same suite: do not count them twice. Startup Python discovery
has 24 functions (19 existing plus five new retained-PE binding negatives).
Formatting, Clippy and these local suites passed before checkpoint publication.
Cross-host v2 execution is pending until its own exact-head CI passes.

The preceding d0bae555 dedicated run 40606202326 passed original Windows probes
and the v1 handler-slice native comparison with retained PE rebinding. That
comparison does not establish v2 acceptance or full startup support. Historical
Windows timeouts remain unexplained; no retry masks failure or relaxes thresholds.

## Remaining critical path

A production entry certificate must derive the original registration/handler
selection and valid initial thread/context ownership from actual entry semantics.
Then lift original scope cleanup bodies and selected-handler unwind/nonlocal
restoration, including faults and external effects, before whole-image admission.
The new resume path removes the context-transform-only gap inside the explicit
slice cut. It does not remove these startup dependencies. PR #45 remains draft.
