# SUB-579 user-mode thread and encoded-record contract

This closes a design boundary: generic scalar heap fields cannot represent the
first rcedit startup effects. A shared thread state and encoded-pointer relation
are required before integration. This is a proof-state prototype and independently
frozen Windows probes, not a production dispatcher, native startup replacement,
or utility conversion. The original rcedit entry and all production rejections
remain intact. No Windows kernel or driver instructions are implemented.

Follow-through: [BYTES.md](BYTES.md) documents the isolated native byte-backed
component, its checked-memory integration and fourteen Rust tests. The Python
prototype described below remains independent and retains its rejection regression.
The component still has no startup admission or exception-dispatch authority.

## Evidence and provenance

DECISION.md binds the unchanged source-built artifact and concrete entry sequence.
The sequence initializes a security cookie, then installs an exception registration
through FS:[0] before ordinary CRT initialization. The snapshot collector is
bounded static evidence, not a control-flow proof; conditional/indirect targets
and loader effects remain open. The model below is independently specified from
these observed requirements and primary contracts; no CRT/Wine source is ported.

Primary documents read 2026-10-27:
- [Cookie initialization](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/security-init-cookie): initialization precedes protected frames; cookie mismatch causes immediate termination. The documentation does not specify this binary's complete entropy algorithm or the exact termination status.
- [SEH](https://learn.microsoft.com/en-us/windows/win32/debug/structured-exception-handling) and [exception handling](https://learn.microsoft.com/en-us/windows/win32/debug/exception-handling): hardware and software events may divert execution. Continuability does not by itself establish a normal return. Handler/filter effects and unwind must be modeled.
- [Termination handling](https://learn.microsoft.com/en-us/windows/win32/debug/termination-handling): cleanup applies to normal and abnormal exits of a guarded body; process/thread termination has distinct behavior. The frozen probes distinguish these cases.
- [System time](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimeasfiletime): fills a FILETIME with UTC time and has no return value. This is not permission to zero output or infer undocumented LastError preservation.
- [Performance counter](https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter): outputs a counter and reports success; XP or later guarantees success with valid parameters. Invalid pointers are outside that guarantee. This does not prove XP compatibility of this project.

The attempted Microsoft Thread Information Block page was unavailable. FS:[0]
layout evidence in this milestone comes from the pinned x86 instructions, not a
claimed portable public ABI. Exact TEB/NT_TIB initial state and loader ownership
must still be established for the targeted runtime. No initial -1 sentinel is
silently assumed for arbitrary original processes.

## Reusable state boundary

A process owns numeric guest mappings and lifetime generations. Threads have
separate FS bases, initial chain observations and active frame stacks. A proof
pointer carries process, owner, generation and numeric address; those facts must
come from validated maps and instructions, not caller-asserted integers. Metadata
is never substituted for guest pointer bits. Cross-process pointers and retired
owners are invalid even if the numeric address is reused.

A cookie is a module-scoped 32-bit value with an initialization/version fact.
The prototype models one cookie domain per process instance; multi-module cookie
domains require explicit module identities before production integration. It
accepts an already established cookie value, not an entropy implementation.
Nondeterministic time, IDs, counter and guest stack addresses remain inputs to the
original code. Results depending on their exact numeric values need an explicit
observation contract; sampled equal output cannot justify replacing those values.

Encoding records the relation encoded_bits = pointer_bits XOR cookie_bits. Decode
requires the same live target, module cookie version and full relation. Numeric
coincidence does not create provenance. This relation is reusable for protected
scope fields; it does not claim all CRT record formats use that encoding.

Typed word storage requires full initialized range and live destination/target.
Any overlapping byte write removes the typed fact, including an identical-byte
write; reconstructing it later requires new proof. All aliases share invalidation.
Byte facts alone cannot authorize a pointer load. Active registration intervals
cannot overlap. A write into an active record marks its thread unresolved. Unknown
external effects invalidate typed cells and cookie knowledge and block all active
thread continuation. More precise effect footprints may retain unrelated facts
only after independently validated contracts exist.

## Registration, cleanup and failure state

The prototype's register transition requires a live 16-byte record range and a
proven encoded scope. Thread identity and nested LIFO restoration are explicit.
An active record prevents its storage lifetime from ending. Restoration requires
an intact encoding relation and no unresolved event. These are necessary proof
obligations; register does not execute __SEH_prolog4, initialize actual record
bytes, establish a handler code target, or issue an executable eligibility token.
Those missing operations are mandatory integration gates.

An exception event produces dispatch-required and blocks all ordinary model
operations process-wide: loads, stores, pointer encoding/decoding, allocation,
thread creation and restoration. This conservative barrier also covers alias
writes into active records. It does not claim that independent Windows threads
actually stop; finer thread/effect isolation is a future proof obligation.
There is deliberately no transition turning that marker into success. A future
shared dispatcher must model first/second chance behavior as applicable, handler
search, filters, continuation restrictions, unwind/termination handlers and
nonlocal register/stack restoration. Unknown handler code, unsupported exceptions,
external mutation or incomplete effect contracts prevent admission. Runtime exit125
cannot be advertised as equivalent Windows exception dispatch or cookie failure.

The model permits an empty initial chain only as a test premise. Its budgets are
64 owners, 32 threads and 64 records per thread; these are experiment bounds, not
Windows limits. Python dataclasses are test representations, not unforgeable
production capabilities. Concurrent execution, fibers, cross-thread unwind, APCs,
debugger effects and asynchronous mutation remain unmodeled.

## Independent expectations and evidence classes

Eleven model tests use literal address/byte relations and adversarial transitions:
identity and reuse, partial alias overwrite, global external invalidation, nested
and cross-thread cleanup, overlapping active ranges, cookie generation, tampered
encodings, unresolved exceptions and complete-word boundaries. Three inherited
inventory tests validate evidence collection. None execute Windows or emitted ELF.

probe-frozen.json fixes source SHA256, ordinary CRT /O2 /GS configuration and five
literal expected byte/exit outcomes before execution. Original Windows probe modes:
normal BF/0, unwind BFH/0, continued search BH/0, resumed execution BC/0, and direct
process termination B/23. WriteFile emits bytes immediately; buffering cannot hide
whether a finally ran. No exception is inferred from output alone: each authored
mode explicitly requests its control-flow scenario. Probe observations do not prove
rcedit's handler graph, original incoming state, or all exceptional paths.

## Production acceptance gate for this same cohesive milestone

The generic model owner has no stack/module/permission class. Therefore it cannot
prove that a registration lives in the correct thread stack or that a scope/handler
is in a valid immutable module. Model constructor premises are test inputs, not
validated incoming Windows process state. Registration does not prove a record
initialized, cookie entropy secure, or a complete record chain well-formed. These
are blocking integration requirements, not facts supplied by the five probes.


1. Extend checked memory/IR with module cookie versions, thread identity/FS base,
   typed pointer fields and overlap invalidation while preserving numeric bits.
2. Bind actual record layout and scope/handler target ranges to the unchanged
   original artifact. Mechanically lift the observed prolog and restoration with
   all stack/register/flag effects. Never dispatch by application hash or name.
3. Close each entropy API and startup predecessor effect, including complete
   output ranges and failure/unknown paths. Retain full graph bounds and reject
   unsupported branches. No kernel implementation is required for user-mode state.
4. Implement or soundly discharge every reachable exception path. Merely observing
   no exception is insufficient. A restricted no-fault domain must be proved for
   all admitted inputs and external effects, with original exceptional paths still
   represented as unsupported rather than deleted or silently successful.
5. Compare unchanged compiler artifacts on Windows and native ELF, including
   normal and adverse paths, stable source/PE/Rust hashes, independent register/
   layout variations and held-out project families. Cookie/address differences
   need relational observations; do not compare arbitrary sampled secrets.

Review this contract/model boundary before production widening. Full utility
admission and the original-startup effect closure remain open. This advances the
shared design beyond isolated accessor probes without claiming native execution.
