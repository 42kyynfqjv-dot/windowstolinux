# Original UCRT reference acquisition and normal EH4 cleanup

Later checkpoint: [locale publication and original UCRT return](UCRT-LOCALE-PUBLICATION.md) continues beyond this historical first-reference boundary.


The explicit second-fiber native-profile component now executes original helper
`0x409efb`, entered by CALL `0x40a0d0`. Its original EH4 prolog installs a nested
record into the same live startup registry, beneath the current UCRT getter call.
The actual indexed EnterCriticalSection helper acquires the lock chosen by the
original argument (logical lock 5 on this path). Original pointer loads select
the multibyte reference word, `LOCK INC` updates that live word, and original cleanup
`0x409f41` releases the matching lease. The independently proved original epilog
unlinks the record, restores saved state and returns with `RET 12`.

Original entry now rejects at **CALL `0x40a0f9 -> 0x40a00d`**, the next locale
publication helper. The first reference increment, original UCRT stores, published
868-byte allocation and getter record remain live. The first helper's lease is
released and its record retired. This is component execution, with no new whole-PE
translation, Windows/ELF comparison or full startup/rcedit/default admission.

## Shared instruction and ownership contract

The IR normalizes only the exact locked 32-bit memory INC form. Default emission
rejects it unless a consuming proof provides an explicit effect contract. Locked
word/register INC and XADD still reject. This does not grant general atomic or
concurrent guest execution.

The consuming helper binds its original code, prolog, epilog, cleanup, imports
and actual protected CALLs. It carries the existing NormalCallEpoch through the
native PTD lazy callback; the callback cannot create an independent registry or
use a supplied successful continuation. Original prolog arguments determine the
EH4 layout. The original normal epilog validates the live record, cookie, saved
registers, predecessor, stack and single-use return ownership.

The reference operation requires active initialization, a live indexed-lock lease,
canonical process-image identity, aligned writable initialized module storage and
a fully known scalar counter. The target is obtained from the actual original
loads. A fully known numeric guest address can select a checked word in the same
process image; it cannot grant heap, foreign-module, stack or unknown-pointer
authority. Pointer values must match that same canonical mapped view. Opaque lock
bytes and protected values reject through the existing memory checks.

The runtime checks and writes the wrapping 32-bit increment; the CPU layer derives
ZF/SF/OF and preserves CF. The runtime remains independent of CPU definitions.
The startup component is serialized: no external callback or shared-host access
occurs between read and write. This establishes the instruction's behavior in that
restricted domain, without claiming a general host-atomic implementation.

Cleanup runs at its original call point. If cleanup code or release authority
fails validation after the increment, the prior count/store remains and the live
EH4 record and held lease remain; no synthetic unlock, unlink or successful return
is issued. These are normal-path semantics. Actual exceptional dispatch/unwind
within this helper remains unsupported and needs its own containment proof.

## Validation and review

Forty independent component scenarios cover zero/one/wrapping/signed-overflow
counter boundaries, stale/replaced leases, foreign thread/image, unknown counter,
ended initialization, retired storage, unaligned access and opaque lock bytes.
Expected-success cases require an actual returned success and exact count/flags;
negative cases assert rejection and unchanged prior counter/flags where accessible.
Four additional original-PE mutations cover body, epilog, cleanup and shared prolog.
The cleanup mutation asserts the increment survived with a live normal frame and
held lease; other relevant mutations reject before the increment.

The existing mixed C++/EH4 startup path is exercised without supplying a completed
helper. The full CRT and artifact replay retain prior nested/lifetime/alias tests,
original wrapper comparisons and source/PE/Rust hash checks. The final replay passed both artifact-dependent tests and five recorded Windows
wrapper comparisons, with zero new Windows/ELF pairs. Repeated Rust SHA-256 is
`af15d5510bce3b3bb1da071e11fd50cb573b14210a305a74bf374613684f22ec`. The full suite passed290 tests, with two artifact-dependent
ignores checked separately; Clippy/format and76 Python tests (one skip) passed.
Exact completed
results appear in [evidence](evidence/ucrt-locale-reference.json).

Review found and corrected an initial layering defect: putting a CPU type in the
standalone runtime broke its isolated compilation tests. Memory updates now return
the old scalar to a CPU adapter that handles flags. A truncated prolog extent and
an initial reference-count oracle were also corrected from original bytes/data;
the runtime-layer compilation failure is retained. A replay against superseded source was stopped
and retained separately before starting the final frozen-source replay.

## Remaining connected gate

`0x40a00d` needs its own EH4 scope `0x41b600`, original lock-4 lifecycle and the
actual pointer-bearing arguments to `0x40a296`. That replacement body reads the
prior locale pointer, may release references, stores the replacement at UCRT
`+0x4c`, then calls `0x40c4ad`. Its optional child references and six-entry traversal
must preserve initialized bounds, lifetime, wrapping and cleanup order. Destructor
`0x40a100 -> 0x40a121`, XADD/release, failure/free/errno closure and the original
getter/startup return remain open. No locale-completion or destructor authority is
issued merely from this first increment.

The preserved case-19 original-Windows timeout remains unresolved. No timeout
threshold, retry policy, formal approval, merge or release changed here.
