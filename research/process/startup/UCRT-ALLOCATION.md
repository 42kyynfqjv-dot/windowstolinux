# UCRT allocation and initializer prefix

Later checkpoint: [first locale reference and normal EH4 cleanup](UCRT-LOCALE-REFERENCE.md) continues beyond this historical initializer boundary.


This component continues the unchanged authored x86 entry under the explicit
`w2l-native-second-fiber-20348-2398cc6a-v1` profile. It executes the original lazy
body at `0x40a1ee`, sentinel setter, calloc body at `0x407cf0`, native checked heap
allocation, original pointer publication and initializer prefix at `0x40a067`.
It now rejects at **CALL `0x40a0d0 -> 0x409efb`**, before the first locale reference
helper executes. Callback 7, the UCRT getter and startup have not returned.

This is component execution using original instructions from an unchanged PE.
It is not a whole-PE conversion or a new Windows/ELF comparison. Default admission
still rejects the provider boundary at `0x402b00`; full startup and rcedit remain
unsupported. The five retained original-Windows wrapper comparisons concern
those wrapper components, not the newly connected allocation path.

## Allocation and publication contract

The original code requests `calloc(1, 0x364)`, or **868 bytes**. The view binds the
fresh canonical Buffer capability after the protected allocation call returns.
It requires the same live process index, current stationary fiber and published
sentinel, exact root extent, initialized zero bytes, and an allocation absent
from the before-call identity set. No bytes are copied and no pointer is retagged.
The original setter publishes that exact pointer before the initializer executes.

The 40-byte VCRUNTIME dispatcher view remains separate. Its existing accessor
still requires that layout. UCRT cannot authorize a C++ dispatcher read, become a
FILE buffer, move to another FLS slot or acquire a fresh lifetime through an alias.
Successful/free-failure retirement removes view authority through the existing
heap machinery. A view establishes storage identity and bounds, **not completion
of locale initialization or authority to run a destructor**.

Native allocation uses the process heap already published by original startup.
The adapter validates the real named import, initialization lifetime, opaque heap,
flags, size, protected stdcall return, saved registers and stack extent before
allocating. It executes checked native allocation with `HEAP_ZERO_MEMORY`; it
never replaces unknown heap exception policy with `false`. Native capacity or
allocation failure rejects the component and retains prior effects. It does not
produce a guest NULL, errno, LastError or exception outcome. Therefore Windows
resource-failure equivalence, original calloc retry/errno, failed publication and
free-error closure remain explicit admission gates. This success-domain native
resource policy does not establish equal Windows and Linux memory availability.

Primary contract: [Microsoft HeapAlloc](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc),
checked 2026-10-30. It specifies zero initialization under flag 8, heap identity,
allocation lifetime and different failure behavior under exception policy. The
native checked heap retains its existing requested-size/alignment limits; no
address-placement equivalence is claimed.

## Original effects and rejection boundary

The original initializer writes these fields before calling the locale helper:

| Offset | Width | Value |
| --- | --- | --- |
| `0x18` | 32 | `1` |
| `0` | 32 | `0x415ef0` |
| `0x350` | 32 | `1` |
| `0x48` | 32 | `0x41c240` |
| `0x6c` | 16 | `0x43` |
| `0x172` | 16 | `0x43` |
| `0x34c` | 32 | `0` |

The shared IR now normalizes the exact word memory-store form `66 89 /r`.
Execution uses the existing width-aware checked store; it preserves flags, source
upper bits, adjacent bytes and unknown bits. Truncated pointer bits remain scalar
bits and grant no pointer authority. Protected return values cannot be truncated
into ordinary data. Word register destinations, address-size overrides, locked
MOV and unsupported prefix forms continue to reject.

At the locale rejection, the 868-byte allocation and current-fiber publication
remain live, the listed writes are retained, and the outer getter's actual
C++-style registry record stays linked. No synthetic rollback, unlock, free,
LastError restoration or successful return is performed. Mutation tests separately
verify rejection before lazy entry, after sentinel publication, after pointer
publication but before initializer writes, and before the original setter thunk.

## Verified tests and retained attempts

[Final evidence JSON](evidence/ucrt-allocation.json) records source, original PE,
generated Rust and report hashes. The final run passed 289 CRT tests (the two
artifact-dependent tests passed separately in the completed replay), 76 Python
tests with one existing skip, Clippy and formatting. Repeated generation matched
Rust SHA-256 `530b910466976d99cccf0a0a15d5bcdf98d3e1389065080d3d010fa14e7292d4`.
The five recorded Windows wrapper comparisons passed; there are zero new
Windows/ELF or whole-PE pairs. Predecessor `783be26` workflows `41110024324`,
`41110013482` and `41110013323` all completed successfully. New-head CI remains
required after publication. Focused cases
include 21 independent allocation/layout/lifetime scenarios, 30 word-store
executions across six source registers, and four additional original-PE code
mutations. They cover truncated/uninitialized storage, wrong layouts, reused roots,
interior aliases, stale and foreign fiber/heap authority, resource rejection,
failed-free invalidation, repeated publication/release and partial effects. The
failed-free case supplies an outcome to the existing heap contract; it does not
execute original UCRT cleanup or add a Windows failure observation.

During review, the generic view validation was narrowed so legacy VCRUNTIME
callers cannot silently accept UCRT. An old test that rejected every word store
was updated to retain negative coverage for unsupported word register destinations,
address-size overrides and locked forms. The new independent word-store test's
initial oracle was corrected for existing zero-extension knowledge and numeric
pointer truncation; implementation rules were not loosened to satisfy that oracle.
Local failed attempts remain in the evidence directory.

## Next cohesive locale and cleanup gate

Inspection of the actual PE establishes this dependency chain:

| Original body | Required effects still unbound |
| --- | --- |
| `409efb` / cleanup `409f41` | EH4 registration with scope `41b5e0`, logical lock 5, pointer-bearing caller arguments, `LOCK INC` at `409f20`, matching cleanup and `RET 12` |
| `40a00d` / cleanup `40a05b` | EH4 scope `41b600`, logical lock 4, two actual pointer-bearing arguments, `40a296`, matching cleanup and `RET 12` |
| `40a296` | Prior locale-reference release when present, replacement store at UCRT offset `0x4c`, reference acquisition through `40c4ad` |
| `40c4ad` | Root/optional child reference increments, six-entry traversal, `40c672` child helper |
| FLS callback `40a100 -> 40a121` | Ordered field frees, multibyte release `409f4d`, locale release `409fb8`, then root free `407d50` |

These are observed dependencies, not a claim they all execute on the current
initial state. Existing locked IR covers OR/AND only; INC/XADD are not admitted.
The next implementation must bind the same live startup epoch to both EH4 frames,
resolve real pointer-bearing mapped fields without deriving authority from arbitrary
integers, and validate reference storage/ownership under the correct indexed lock.
It must preserve x86 wrapping and flags and execute cleanup exactly once, retaining
earlier writes on later failure. Dynamic reference release, nondefault locale
branches and initialization/free failures must remain rejected until proven.
Do not install a successful locale callback or mark initialization complete merely
because the allocated bytes began at zero.

Sol can review this allocation/width/publication slice. A bounded Astra High pass
is appropriate for the combined EH4/locale reference and atomic-lifetime question;
routine CI and evidence checks do not need escalation.

The predecessor case-19 original-Windows timeout in run `41107853543` remains
unresolved. Its artifact and diagnostics are preserved in the previous evidence;
a later passing run does not establish its cause. No timeout threshold or retry
policy changed here.
