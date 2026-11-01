# Original locale comparison and uninitialized allocation

This records1a9c0ab. [The connected copy checkpoint](LOCALE-REP.md) supersedes
its former execution boundary.

Under the explicit native UTF-8 process profile, original entry executes
`0x40b267` argument cleanup, selected-code-page store and live reference
comparison. The differing-code-page path calls the complete original malloc
body at `0x408730`. Actual HeapAlloc flags0 produces a fresh, owned 544-byte
Buffer with **unknown contents**. Malloc's original normal epilog returns it;
execution rejects at `0x40b289`, before storing the pointer into the caller's
local slot. The locale-initialized flag stays zero.

The equal-code-page branch executes original XOR, jump and aligned epilog.
The original callback then writes its flag and returns AL1 without allocation.
This branch is checked with declared matching-reference inputs. It is original
control-flow behavior, not an attestation that an arbitrarily modified locale
table is a valid encoding implementation.

## Shared heap and authority

The bounded native Buffer producer now supports flags0 and flags8. Both use the
same process heap and fresh allocation identity. Only flags8 initializes bytes
to zero. A load from flags0 memory retains unknown scalar bits; it cannot acquire
a Pointer tag or PTD/descriptor/FLS/locale role merely by reading those bits.
Descriptor construction still requires flags8; its separate role checks are
retained. Existing PTD tests continue rejecting uninitialized layout admission.
Aliased pointers expire with the original allocation.

The stdcall adapter checks the live protected return, saved registers, stack
extent/permissions, opaque heap handle and fully known flags/size **before**
allocation. No guest callback runs between allocation and return. Its success
result grants access only to the fresh allocation's actual extent. Internal
budget or host-resource exhaustion rejects; it is not a fabricated Windows NULL,
LastError or exception outcome.

Primary [HeapAlloc contract](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc)
states that memory is not initialized unless HEAP_ZERO_MEMORY is selected.
This slice supports flags0/8 and bounded nonzero native requests, not arbitrary
heap flags, exception modes or resource-failure equivalence. Original malloc's
zero request becomes one byte through its actual instructions before the API.

## Original effects and failure tests

The caller binds its actual disjoint instruction ranges, branch target and return
epilog. The selected reference is resolved through the canonical mapped image;
unknown code-page words cannot choose a branch or allocate. The explicit GetACP
profile still must match the same live process encoding token. No encoding
default or extra pointer authority is inferred.

Malloc and mode-getter bytes and HeapAlloc's named import are bound to the
unchanged authored PE. The real native entry uses the checked native allocation
producer. Separate conformance inputs inject failed API observations to exercise
the original failure branch and actual mode getter. Errno acquisition and
new-handler invocation remain explicit unsupported effects: no successful errno
write, retry, free or exceptional cleanup is invented. Earlier writes, completed
allocations and interrupted call state survive later rejection.

Coverage includes:

- Four allocation sizes, partial initialization, independent allocations,
  zeroed controls, failed scalar-to-pointer conversion and expired aliases.
- Ten invalid allocation/resource/role/lifetime cases and five stdcall cases.
- Eighteen original malloc cases: actual success and zero-size normalization,
  oversized requests, declared NULL observations, mode branches, failure after
  a write, failure after completed allocation, stale/foreign heaps, unknown size,
  capacity rejection, changed code/mode/import/flags, and original error ordering.
- Thirty-four entry/getter/reference cases, including equal-code-page return,
  changed caller/epilog/allocator and an unknown reference code-page word after
  the preceding argument cleanup/local write.

These constructed inputs are component tests; they do not become fresh Windows
allocation-failure observations. The actual entry test obtains the heap from the
original startup producer. The isolated locale fixture explicitly publishes the
same canonical heap handle instead of weakening the API's publication check.

## Review, evidence and next scope

Review of `e17247d` verified source hashes, actual selector branches, unknown
state, same-token ownership and original effect ordering. All three exact-head
workflows41269413336/41269409929/41269409920 passed. No predecessor runtime defect
was found. Retained local failures show obsolete boundary/allocation-count
expectations and the isolated fixture's missing heap publication; original
rejection checks were preserved.

Next execute the original local pointer store/pop/test and bounded copies at
`0x40b2b6` and `0x40b2c2` before the initializer at `0x40b485`.
REP-prefixed instructions currently reject in shared lifting. A reusable copy
contract must preserve count/register progression, initialization, typed aliases,
overlap, bounds and partial effects. Existing `Cdecl32Forward` explicitly
requires DF=0; unknown Windows direction flags must not be silently cleared.
Then bind GetCPInfo/validation, publication and reference release before full
multibyte initialization acceptance. Sol can continue the bounded stores/copy
design; escalate a concrete ownership/proof ambiguity if one is demonstrated.

Full startup/rcedit/default admission, broader Windows encoding equivalence,
heap-reference freeing, exceptional EH4 cleanup, capture/delivery/collided unwind
and native close/EOF remain unproved. Historical Windows case19 timeout and other
retained failures remain unresolved. Component wrapper comparisons are not
unchanged whole-PE translation.

See [evidence](evidence/locale-malloc.json), [dependency map](DEPENDENCIES.md)
and [previous selector contract](LOCALE-CODE-PAGE.md).
