# Original onexit fill and first publication

## Connected execution

Under the existing explicit native, UTF-8, CPU/entropy and stationary x87
profiles, the unchanged authored entry now completes its first onexit
registration. Original `0x40c8ae -> 0x402370` fills the real 128-byte allocation;
it is not replaced with a zeroed allocator. The append body then actually
executes the cookie fill, original encoder `0x406d62`, callback store
`0x407395`, and begin/next/limit stores `0x4073a0/0x4073b0/0x4073bf` into
canonical table `0x41ce88`. The original registered manager releases logical
lock 2 and executes its checked EH4 epilog/RET12. The wrappers return status 0.

The next rejection is **before CALL `0x40159b -> 0x401bbf`** in the first C
initializer. Its callback argument remains on the original caller stack. The
root startup scope/state and earlier effects remain live. This is connected
native component execution from a mapped unchanged artifact, not whole-PE
conversion or full rcedit support. Default admission remains unchanged.

## Authority and unsupported paths

The empty-table domain requires three scalar words equal to the cookie. The
allocation capability comes from the actual canonical heap producer and remains
the same object through recalloc, memset, fill and publication. The callback
input is bound to the immutable image target and active protected call. Before
each original publication store, the compiler-generated checks validate that
allocation, table, cookie, lock, event/frame authority and expected encoded role.
The checks do not replace the stores or skip original effects.

Encoding discards pointer authority; it never creates it. The table contains
scalar encodings, not retagged pointers. **Nonempty decoding, repeated
registration, growth/reallocation, callback invocation and exit-table traversal
remain rejected/unbound.** A correct encoding naming an existing live buffer
still cannot issue ownership. A future persistent producer association must
bind table/allocation/callback identities and invalidate on overlapping writes,
cookie changes, free/resize, code/module retirement and event expiration.
It must not resurrect authority by noticing equal bytes after an unknown write.

The first-publication transaction is confined to the current active call. It
issues no persistent callback invocation or cleanup authority. Non-null free,
malloc errno/new-handler, allocation-failure equivalence and exceptional EH4
cleanup remain separate limitations. Resource exhaustion is rejection.

## Instruction semantics and failure effects

The original memset graph includes scalar stores, REP STOSB and enabled SSE2
MOVD/PSHUFD/MOVUPS/MOVDQA/MOVDQU paths. The structural additions grant no CPU/OS
feature premise. Existing explicit feature state chooses the actual path. MOVD
preserves low-lane knowledge and zeroes upper lanes; PSHUFD reads its source
snapshot and preserves flags. Pointer alignment retains only an existing live,
bounded stack/buffer capability. Numeric end-address arithmetic discards it.

REP STOSB/STOSD require their own explicit memory-effect issuer; neither a
thread hook nor a REP-copy hook can admit them. Only the existing DF=0 cdecl
domain is supported. Count zero does not observe the REP destination or value;
the original memset still loads its arguments. Completed elements retain their
writes and EDI/ECX progress if a later access fails. Other REP encodings/STD reject.

The independent byte oracle exposed a shared no-op LEA defect: `LEA EBX,[EBX]`
converted a saved opaque identity into unknown scalar bits. The exact identity
form now preserves it. Nonzero arithmetic still cannot recreate that identity.
Pointer forms keep their existing live-capability validation.

## Evidence and review

[Frozen expectations](evidence/onexit-fill-expectations.json) precede the local
implementation. [Results and hashes](evidence/onexit-fill.json) record checks,
source/artifact identities and failures. The focused oracle covers 5,056 complete
memset cases across four scalar/SSE2/ERMS feature combinations, all 16 alignment
offsets, zero/small/vector/loop/tail boundaries and 1,024-byte fills. It checks
that bytes outside actual stores stay unknown. Separate cases cover REP partial
progress, stale storage, control-value rejection, SIMD lane knowledge and no-op
LEA identity. Encoder tests cover all 32 rotation counts, four scalar patterns,
live allocation inputs and stale aliases; outputs never become pointers.

The 22 manager scenarios include real successful first publication, changed
memset/encoder/store code, a late table-write permission failure (cookie fill and
callback write survive), unknown feature state, missing allocation authority,
and a repeated real registration that rejects without duplicating allocation.
Routing-result callbacks remain explicitly labeled component cuts.

The five retained recorded original-Windows wrapper comparisons are component
evidence. There are **zero new whole-PE Windows/ELF pairs**. Earlier case5,
case19, hello and other original-Windows launch timeouts remain preserved and
unexplained; passing later CI does not diagnose them. No timeout/resource limit
was raised. PR #45 remains draft and SUB-579 remains In Progress.

Next Sol review: original byte bindings, REP effect isolation/progress, SIMD and
LEA knowledge, actual four publication stores and cleanup, lifetime failures,
and exact-head CI. Next execution boundary is the first initializer's
`0x40159b -> 0x401bbf`; persistent encoded-pointer decoding is a distinct hard
ownership gate, not authority inferred from these successful stores.

### Read-only inventory of the next connected scope

The next target `0x401bbf` is `XOR EAX,EAX; INC EAX; RET` (returns 1).
The following original call `0x4015a1 -> 0x4069d4` tail-jumps to `0x4066d6`.
Its mode-1 path calls the existing locale initializer, then `0x406722 -> 0x40ae0d`.
That wrapper actually imports **GetModuleFileNameW** at IAT `0x415084`, writes a
261-WCHAR checked local buffer, maps failures through GetLastError/errno, and
passes through narrow conversion helpers before its cookie epilog. It then
feeds original argument count/allocation/parsing and argc/argv publication.
These instructions are inventory, not newly executed or supported behavior.

The next coherent scope is mode/argument-configuration execution using canonical
process image-name and command-line producers, bounded wide/narrow conversion,
and owned argv storage. Preserve profile-specific path/encoding semantics,
truncation and failure effects, parser count-versus-write agreement and cleanup.
Do not substitute the original Windows path, Linux output path, supplied argv or
locale defaults without a declared producer contract. Sol can review and start
this connection; escalate a concrete producer/lifetime uncertainty if necessary.
