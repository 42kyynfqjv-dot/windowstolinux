# Original FILE initialization and canonical lock ownership

The explicit controlled native-profile entry now completes the unchanged FILE
initializer at 0x404510 and reaches locale callback **0x4109ba**. Both empty and
three-entry environment variants retain their independently owned strings after
this progression. Full startup/default/rcedit admission remains unsupported.

## Executed original instructions

The body normalizes the stream count, executes original calloc at 0x404532,
publishes the allocation at 0x41cd30, and executes its original NULL-free wrapper.
Its fallback allocation and failure return remain present. Native resource errors
reject; they are not fabricated guest NULL/BOOL/errno outcomes.

The original loop executes the validated 0x408079 prolog and IAT tail jump to the
established InitializeCriticalSectionEx replacement, with actual 12-byte stdcall
cleanup. Each successful constructor precedes the original FILE-vector slot store
and descriptor-handle classification. All three records execute before the real
register restoration/RET. The zero-initialized vector has its original capacity;
its FILE pointers refer to canonical mapped storage, not copied FILE objects.

Only the original initial cursor constant is bound to the existing issued FILE
view after checking its shared section identity, owner and 168-byte bounds. Later
loop cursors retain that view and must validate as records in it. Module section
bounds cannot replace the narrower FILE role. Exact body/thunk/import guards stay
in place.

## Native resource and ownership contract

The existing FILE-lock set is now a vector-backed set with fallible reservation.
Runtime creation
and construction reserve storage before insertion; membership, removal, duplicate
checks and teardown semantics remain shared with existing lifecycle code.

Native construction requires live initialization, the established synchronization
export/provider, a writable 24-byte range at FILE+32, spin4000, flags0, a complete
canonical FILE record, no typed aliases and no existing lock. Metadata is reserved
before bytes become opaque. Only actual membership construction yields success.
There is no supplied API-success parameter and no invented critical-section byte
layout. Descriptor locks retain their separate layout and ownership.

Primary API semantics follow the repository's existing
[InitializeCriticalSectionEx](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsectionex)
contract and measured native-profile restrictions. Host resource rejection does
not establish Windows allocation-failure equivalence. Lock leases still enforce
thread ownership and block destruction while held. Destruction/reinitialization
uses the same canonical membership; repeated or stale operations reject.

## Independent checks and remaining gates

Eleven native lock cases cover duplicate/misaligned/wrong-role objects, typed
aliases, expired initialization, changed thread/provider, partial construction,
spin/flag rejection and destruction with a live lease. An independent allocator-denial
case checks reservation failure and all three preallocated constructor effects. Eleven original-body cases
cover default/minimum/custom capacity, actual vector publication and all three
FILE slots, changed body/thunk/free code, absent descriptors, duplicate first or
second lock, unknown later descriptor data, and oversized allocation/error-path
rejection with the preceding count store preserved. Partial failures retain prior
locks and slot stores. No cleanup or normal return is invented after rejection.

The canonical entry gate verifies three constructed FILE locks, the 512-slot
vector, exact FILE pointer identities and the next original array target0x4109ba.
Existing lifecycle fallback/teardown tests and all low-stack cases remain required.
The integration initially exposed a missing set len adapter in generated lifecycle
code; it was repaired without weakening that coverage. A thunk-fragment early
host return and a repeated cursor-binding rejection were corrected before publish.

The next bounded scope is original locale callback0x4109ba and its repeated locale
helper call. Inventory existing locale-state/reference lifetime and reuse semantics
before binding it. Exceptional cleanup, resource-failure equivalence, broader
thread support, copy-error termination0x407b5f and full startup remain unproved.
Historical Windows timeouts remain unresolved. Inputs/evidence use synthetic
controlled environments only; no host environment values are acquired or logged.

Local validation: 358 aggregate CRT tests plus the independently passed allocator-denial
case; canonical entry/body cases, 114 Python tests (one skip), Clippy warnings
denied, formatting and all 152 word cases at 512 KiB plus 64 KiB padding pass.
Final published-source replay and full CI remain separate verification gates.
