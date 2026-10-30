# Original startup lock and FLS control

The original entry now reaches CALL402c42 to the shared resolver402a53 through
40195a→4024ca→4029b4→402c2d. The constructor's original prolog, saved ESI and four
resolver arguments execute. That resolver remains unbound on this entry path;
no lock or FLS allocation success is injected. Canonical image/code permissions,
initialization identity and protected call/return checks apply at every region.
The earlier cookie and classifier writes remain at rejection. This is a bounded
component path with supplied root activation/stack/incoming-chain premises.

Six regions (245 bytes) bind their actual original instructions. Five are closed
functions; the constructor prefix is an explicit fragment whose final call
rejects. The shared emitter lowers their normal branches, count/slot stores,
cleanup loops and returns. Changed original bytes reject source generation;
a separately changed live module body rejects at runtime. Full startup/rcedit
remains unsupported.

Nine component cases separately exercise the original module dispatcher, lock
loop/destruction and FLS publication control. The lock-construction result,
FLS allocation result and destruction effect are **explicit supplied component
boundaries**. They are not original Windows observations, native allocation or
proof that these API wrappers execute. The successful lock observation is applied
to the existing distinct module-lock owner model, with alias/stale checks.
The tests verify failure before count publication, FLS_OUT_OF_INDEXES publication,
cleanup of the earlier lock, preservation of slot/count/owner on publication or
cleanup rejection, expired initialization, tagged/overlapping lock aliases and
changed live code. Returning cases require successful execution and AL=0; the
upper EAX bits remain unspecified after a void effect and are not invented.

FLS success does not mint a slot or PTD owner in these cases. The original
publication arguments are inspected: index7 and raw value41ccc4. Execution stops
at the publication effect rather than copying or retagging that value into a
heap/ThreadData owner. Publication and cleanup failures in these tests are
component callback rejections, not modeled Windows FALSE or exceptions.

## Exact remaining contracts

1. Lock wrapper402c2d requests dynamic resolution at402a53 before either guarded
   indirect execution or fallback InitializeCriticalSectionAndSpinCount. Extend
   the existing resolver's symbol/cache/module lifetime proof to this actual
   constructor, including flags/spin count, failure and opaque24-byte lock state.
   Do not treat a cached numeric function address as initialization permission.
2. FLS allocation wrapper402b3e resolves dynamically and has a FlsAlloc fallback.
   Bind callback4028a7 and process-wide slot allocation/retirement separately
   from the current fiber value,
   module lifetime and failure contract before granting FLS ownership.
3. The value41ccc4 is distinct from the recursive initialization markerFFFFFFFF
   used by the lazy getter. Original destructor4028a7 explicitly skips free for
   both null and41ccc4; the next module object starts40 bytes later at41ccec.
   This supports a distinct module-backed bootstrap-object path, not a heap PTD
   or the recursive-initialization sentinel. Establish its actual40-byte view,
   initialization and mutation contract and destructor lifetime. Current
   `fls_value`/`dispatcher_ptd` accepts explicit ThreadData or validated heap PTD
   views and rejects this module-backed representation. Preserve canonical
   allocation identity; do not relabel module bytes as a heap allocation.
4. Connect actual setter/free wrappers402bef/402b79 with original success/failure
   ordering: publish41c060 before setter; failed setter frees the slot and resets
   the global; outer failure destroys already-constructed locks. Existing FLS
   failure conservatively invalidates value knowledge and cannot imply atomicity.

A bounded Astra pass is useful for the module-backed bootstrap PTD view and its
FLS/destructor lifecycle, plus the constructor/allocator resolver authority.
Routine CI and review can stay on Sol. The existing CPU contract was inspected:
queries remain confined to the closed scalar classifier, preserve architectural
flags/register effects and grant no permission for later SIMD code. Its three
CI workflows were still running at the recorded checkpoint; no parent success
was assumed.

## Validation and local corrections

259 CRT tests passed, strict Clippy passed,60 Python tests passed with one
existing skip. The unchanged-PE replay retains the five earlier Windows
component comparisons; this checkpoint supplies no new Windows CPU/lock/FLS
comparison or whole-program result. Evidence hashes are in
[evidence/startup-module-review.json](evidence/startup-module-review.json).

The first local component test omitted the original empty cleanup call after
constructor failure; the callback binding was corrected to execute it. Another
expected a fully known EAX after a void cleanup effect. The original contract
returns AL, so the test now strictly requires success and known AL=0 while
preserving unknown upper bits. Failure logs remain available. Historical
original-Windows timeout causes remain unresolved.

Primary contracts: [FlsAlloc](https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsalloc) allocates an index usable by any fiber in the process; it is not valid across processes. [FlsSetValue](https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flssetvalue) stores the calling fiber value, returning zero on failure. The current explicit-input fiber-bound slot model must not be mistaken for process-wide allocation authority.

Generated Rust SHA256: `91aeca7f3a6734b32bff0a2e29ca6e15b9d7756e5d6ed7df4bf769d37c6742dc`.
