# Locale startup and checked aligned activation

## Executed scope

The unchanged authored PE is still SHA256
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`.
In the explicit native launch profile, initializer index10 now enters original
callback `0x40b42a`. It writes the three original module addresses to
`0x41d140`, `0x41d13c`, and `0x41d138`, executes required-PTD getter `0x40a2ef`,
and pushes the original four arguments. The original CALL enters `0x40b235`,
executes its aligned prolog and pushes the first body helper's two arguments.
Execution rejects before CALL `0x40b25a -> 0x40b38a`. The initialized byte at `0x41d148` remains zero.
No multibyte initialization, complete callback10, formatter, whole-startup or
rcedit compatibility claim follows.

The getter executes its original C++ registration prolog, static FlsGetValue
thunk, branches and epilog against the canonical live exception registry. The
fast path returns the same published UCRT heap allocation (868 bytes), with its
allocation/slot/fiber identity intact. Repeated acquisition creates no new heap
allocation or view and retires each temporary C++ record. The existing lazy
producer is connected without substituting an allocation result. A required-PTD
termination branch remains an explicit rejection; the trailing trap cannot become
a successful structural return. This does not prove exceptional handler execution.

Unknown values do not become pointers. A view requires the actual UCRT allocation
root, matching live FLS publication and current fiber; the distinct 40-byte
VCRuntime view cannot supply it. Failures preserve completed original stores and
registration effects. A nonzero input flag follows the original skip branch;
that component case does not establish that initialization actually happened.

## Independent evidence and provenance

`check_normal_wrapper.py` verifies callback, getter, handler and alignment-test
bytes directly against executable mappings in the unchanged PE before replay.
The FlsGetValue import and later code-page imports are also checked. Native
regressions cover positive and repeated acquisition, consumed-return replay,
callback/getter/prolog/epilog/handler/thunk/import mutation, missing or stale view,
wrong PTD layout, unknown/sentinel values, stale index/fiber/slot and partial
writes. Twenty declared-state scenarios supplement the connected original-entry
case; their setup is explicitly separate from Windows observations and original
startup producers.

The earlier ten unique Windows Unicode/quoting cases were independently redecoded
from both retained ZIPs. The corrected LF checkout archive's C, manifest and vector
bytes match the repository, and both probe PE hashes were checked. These remain
command-line conformance observations, not new Windows/ELF translation pairs.
The five recorded wrapper comparisons also remain component comparisons.

## Reproduced architectural limit

The original helper begins:

```
40b235 MOV EDI,EDI
40b237 PUSH EBX
40b238 MOV EBX,ESP
40b23a PUSH ECX
40b23b PUSH ECX
40b23c AND ESP,-8
40b23f ADD ESP,4
40b242 PUSH EBP
40b243 MOV EBP,[EBX+4]
40b246 MOV [ESP+4],EBP
40b24a MOV EBP,ESP
40b24c SUB ESP,0x238
```

### Implemented shared contract

The shared CPU now preserves a live stack capability for a known low-bit alignment
mask, with the same-object bounds and protected-word checks. Scalar inputs remain
scalar; unknown masks and ordinary logical operations grant no pointer authority.
Logical flags retain x86 semantics. ADD discards ordinary unknown padding without
inventing initialized values. Partial prolog writes remain visible if a later local
allocation exceeds the owned stack extent.

`CrtAlignedActivation` is bound to the actual protected CALL identity, numeric
continuation, source stack capability, runtime, thread and fiber lifetime. The
complete supported compiler prefix is checked before emission; its local extent
may vary, and it has no application-name, binary-hash or result dispatch. Original
code bytes are independently checked in the mapped PE at execution. The compiler's
mirror MOV stores **scalar return bits**, while the original slot retains the only
protected return tag. Neither the mirror nor an arbitrary numeric stack address
can mint control/pointer authority. Boundary-created CPUs without an observed
CALL continuation cannot issue the lease.

EBX retains the original unaligned frame. Original epilog instructions restore
ESP through EBP and then EBX and RET through the original source slot. The mirror
is not the RET slot. The bounded contract checks an unchanged mirror before
nested-call continuation or normal return; it does not claim to support programs
that intentionally alter that mirror. It neither consumes nor replaces return
authority. Lease replay, source/mirror corruption, wrong caller/runtime/fiber,
retired storage and returning through the mirror reject.

An independent failed-child test exposed that a suspended child's effects could
leave the parent's return-observation lease apparently live. The shared CALL path
now invalidates that metadata on failure or incomplete RET, preserving registers
and prior writes. Rebinding Main after validated nonlocal restoration explicitly
clears unrelated continuation knowledge. This does not implement aligned-frame
exception unwinding: unsupported nonlocal cleanup remains rejection and cannot
produce a normal-return receipt.

### Verification scope

Native conformance executes the original prefix and epilog with two stack residues,
two local sizes and nested depth two (four top-level runs, twelve frame lifetimes).
The intermediate body is explicitly authored test behavior, **not** the locale
body. Eighteen independent negative modes cover mirrors/source, stale runtime or
stack, thread/fiber changes, invalid observation identity, repeated copy, aliasing,
failed child effects, wrong saved registers, nonlocal cleanup and mirror return.
A separate short-stack case checks preserved writes on later failure. Numeric
alignment tests reject out-of-range/stale/protected inputs and keep scalar inputs
scalar. Proof mutations cover every non-size prefix byte, invalid sizes and code
address overflow. The artifact replay additionally checks a changed original
mirror instruction before admission. Twenty declared-state locale scenarios stay
separate from the connected entry producer and Windows observations.

### Exact remaining gate and review handoff

The connected explicit-profile entry reaches **CALL `0x40b25a -> 0x40b38a`** with
its actual UCRT pointer and module-root argument on the live child stack. The
locale initialized flag is still zero; no helper body call is substituted.
`0x40b38a` begins an EH4 frame (12 local bytes, scope table `0x41b660`, prolog
`0x401e60`), reads UCRT offsets 848/76/72 and module state `0x41c7b8`, obtains
logical lock5, conditionally decrements/frees an old multibyte reference, publishes
its replacement, increments its reference and runs the original unlock funclet.
Its null-result termination path at `0x40b424 -> 0x4077ff` must stay explicit. Its
inventoried `LOCK XADD [ESI],EAX` at `0x40b3d8` also needs a shared atomic
read/modify/write contract (old value returned in EAX and correct arithmetic
flags). Current CRT IR/emission supports other locked forms, not this operation.
This is an inventory finding in the unexecuted body, not a new observed entry
rejection after the current call boundary.

Sol independent review should inspect the shared AND/protected-CALL changes,
non-authoritative mirror store, failed-child invalidation and restored Main state,
plus the strict positive/negative tests and exact-head CI. Existing EH4/lock/locale
reference machinery provides the next bounded integration scope at `0x40b38a`;
a new ownership ambiguity would justify a specific Astra pass. Complete locale
initialization is outside this checkpoint. Later `0x40afbc` selects GetOEMCP for
-2, GetACP for -3 and locale state for -4; the original callback selects -3. Its
eventual GetACP must match the declared 65001 native profile. This is not a premise
that Windows ACP is universally UTF-8, nor XP/7 evidence.

The prior pointer-loss and duplicate-authority experiments remain in Git history
at `f390576` and `evidence/locale-startup.json`. New evidence is recorded separately
in `evidence/aligned-activation.json`; five retained Windows comparisons are still
wrapper **component** comparisons, with no new whole-PE translation pair.

Primary contracts for the later code-page work:
[GetACP](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getacp),
[GetOEMCP](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getoemcp),
[GetCPInfo](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getcpinfo).

Default admission, native close/EOF equivalence, incoming Windows delivery and
collided-unwind effects remain unproved. Historical original-Windows case19
process timeout is retained with cause unresolved; no retry or threshold change
resolves it. [Evidence](evidence/aligned-activation.json) records exact local checks,
source/PE/Rust hashes and predecessor CI separately from the new head.

## Reproduction

Use the retained unchanged authored PE and recorded observation directory. These
commands execute Rust component tests; they do not launch a Windows PE on Linux.

```sh
cargo test --locked --example crt_stream aligned_
W2L_PE_MAPPING_INPUT=/path/to/original/unwind.exe cargo test --locked --example crt_stream canonical_image_cookie_and_original_record_initialization_compose -- --ignored
python3 research/process/startup/check_normal_wrapper.py /path/to/original /path/to/observed /path/to/new-output
```

The focused tests require the original prefix/epilog to succeed in the declared
normal-return domain and each negative mode to reject with its expected first
error. They separately test proof mutation and relocated/differently sized frames.
These are frame conformance tests, not an implementation of the omitted body.

## Verified local checkpoint

301 CRT tests passed (two artifact-dependent tests are excluded from that count),
with stricter negative-error assertions also checked in the focused replay.
185 unwind tests and 84 Python tests (one existing skip), Clippy and formatting
passed. The two artifact-dependent checks run in complete replay, including
20 declared-state locale scenarios and the connected explicit-profile entry.
Its report records five retained Windows wrapper component comparisons and
zero new whole-PE pairs. Source, PE, generated Rust and report hashes are in
[evidence/aligned-activation.json](evidence/aligned-activation.json).

The earlier failed replay of this slice expected a saved-register error for a
corrupted EBX. The original epilog first changed ESP and rejected stack identity;
only the test's expected first error was corrected. Its logs remain retained.
The old entry assertion also now checks saved EBX through the actual aligned
frame rather than expecting the previous unexecuted-helper register state.
Neither correction weakens runtime rejection or changes original artifacts.

All three f390576 predecessor CI workflows passed (41262712589, 41262706930,
41262706913). Final publication CI is recorded in SUB-579 with exact head/run IDs;
local passing checks do not assert a final-head cross-host CI result.
