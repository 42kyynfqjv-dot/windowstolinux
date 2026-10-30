# Original descriptor allocation in callback 8

The explicit second-fiber profile now enters initializer callback 8, `0x408697`,
from original indirect CALL `0x40c946`. Its original prolog registers scope
`0x41b5c0`, and its original indexed acquisition holds logical lock 7. The nested
manager at `0x40bf2a` registers scope `0x41b6a0` and recursively acquires the same
lock through its actual table address and checked native lease.

The original manager and constructor `0x40be7a` execute their actual loops.
Original calloc(64, 56) uses the existing canonical process heap. All 64 record
locks initialize, the original descriptor field stores execute, the same
3584-byte allocation is published to `0x41cf08`, and capacity 64 is stored at
`0x41d108`. The original manager cleanup at `0x40bfbf` releases only its own recursive
lease, and its proved epilog returns to the still-active outer callback.

The original inherited-record body at `0x408537` executes to **CALL `0x408543`,
GetStartupInfoW**, where its output-effect contract remains unbound. The outer
callback lock and EH4 record remain. The manager has completed, while callback 8,
standard-handle initialization and overall startup have not.

This is original-instruction component execution under an explicit native profile.
It adds no whole-PE or Windows/ELF comparison and establishes no default admission,
full rcedit or XP/7 compatibility.

## Shared memory, callable and resource contract

Descriptor calloc reuses the original calloc graph and checked native process-heap
producer. Its descriptor role is selected inside the allocation boundary before
any guest pointer escapes. The allocation capability, owner, address and bytes
remain canonical; no existing Buffer alias or PTD is retagged. The 868-byte UCRT
allocation remains a separate Buffer/current-fiber object, and the 40-byte
VCRUNTIME layout remains distinct.

The existing critical-section contract extends to whole checked descriptor slots.
The original static thunk/import binds InitializeCriticalSectionEx, with the
actual native implementation/provider checked on each invocation. Only supported
flags and spin input are admitted. A record object is initialized by forgetting
its opaque lock bytes and issuing its existing owned lock identity. The constructor
then executes its original nonopaque stores. No host-supplied success counter or
per-fixture allocation response drives this path.

Native bookkeeping reserves storage before opaque initialization. Allocation denial
rejects the component before changing the new slot. Existing initialized objects,
allocation identity and LastError knowledge survive. Capacity is explicitly bounded;
resource rejection does not fabricate Windows FALSE, NULL, errno or exceptions.
Windows resource-failure equivalence and original exception/rollback paths remain
unproved. The native component remains serialized; general concurrent guest threads
and unrestricted synchronization semantics are not admitted here.

Original indexed helpers distinguish logical lock numbers from owned table slots.
Both nested frames use the actual live startup epoch and existing prolog/epilog
proofs. Saved state, stack bounds, predecessor identity and unique return authority
remain checked. The manager's separate exception-funclet entry at `0x40bfbc` is not
ordinary fallthrough or supported exceptional execution. No structural-success
bypass substitutes for the original normal cleanup/epilog.

## Validation and retained effects

The connected entry test checks both heap objects, descriptor role/extent, all 64
live record locks, opaque-byte rejection, actual descriptor fields, capacity 64,
retired manager/getter state and the one remaining outer lease. It requires the
exact GetStartupInfoW boundary; output memory has not been initialized by that API.

Twelve independent native resource scenarios test metadata allocation denial before
zero/four completed records, extent constraints, alignment, ordinary Buffer role,
retired allocation, stale provider, ended initialization, foreign thread, duplicate
initialization, flags, live-object destruction and repeated release/destruction.
Failure assertions require no new object or opaque-byte mutation, and retain prior
objects. The denied allocator is restored before test reporting.

Seven additional PE mutations test callback/manager/constructor/cleanup/inheritance
code and the shared lock thunk. The shared thunk rejects earlier in the startup
lock loop, before descriptor allocation; it is not misreported as a descriptor-stage
rejection. A changed manager cleanup retains the already-published capacity/block,
64 objects and both leases. A later inherited-body rejection retains publication
with only the outer lease. The original artifact remains unchanged in positive runs.

Final validation passed 291 CRT tests; both artifact-dependent tests passed in
completed replay. Clippy/format and 76 Python tests (one existing skip) passed. Five
recorded Windows wrapper comparisons passed; zero new Windows/ELF pairs. An explicit
later emission matched Rust SHA-256 `08b6f4cc652cc82536fd2015709b6b2a1d08c30ba33e2091e986f300727209e1`.
Exact final results and source/PE/Rust hashes appear in
[evidence](evidence/startup-descriptors.json). These native component scenarios
are distinct from the existing five recorded original-Windows wrapper comparisons.
The historical case-19 Windows timeout remains unresolved; no timeout threshold or
retry policy changed.

## Next cohesive startup-info and handle gate

GetStartupInfoW must acquire process-owned startup state and establish output
writes, initialized ranges, reserved-block lifetime and aliases. Do not relabel
supplied serialized records as actual acquisition or assume cbReserved2 is always
zero. Then connect the original parser and GetFileType/standard-handle bodies to
actual typed handle producers, retaining invalid/null handles, partial initialization
and cleanup behavior. Existing tests currently supply these outcomes.

Reusing a host file-descriptor number as a guest handle also requires care: host
stdin fd 0 must not accidentally become Windows NULL. Bind canonical host resource
identity and allowed guest observations explicitly. Native allocation success does
not close error/errno, resource-failure or exceptional-unwind contracts.

Sol can review this descriptor/record integration. A bounded Astra High pass is
appropriate if startup-record ownership and native handle identity need a new
semantic contract; routine CI and reproduction should stay on Sol. No formal
approval, merge or release is part of this checkpoint.
