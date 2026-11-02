# Original environment-table construction and current ownership gates

The original caller now executes past0x406a22 into CALL0x406a36→0x406a65.
The unchanged builder counts entries, skipping its original leading-equals
entries, executes original calloc for a separate NULL-terminated pointer vector,
and allocates each selected string separately. No replacement parser or inferred
pointer values supply these effects.

## Observed connected boundaries

For the controlled nonempty launch, original execution reaches the first string
copy helper0x407770. Its prolog and tests execute, then **SUB ESI,EDI at0x4077a8**
rejects unrelated source/destination capabilities. The original x86 code computes
a numeric displacement between independent allocations. At0x4077b0 it intends
to read through displacement plus the destination cursor. The existing checked
model deliberately refuses both unrelated-pointer subtraction and deriving source
authority from a numeric displacement into a different capability.

At rejection the converted temporary buffer remains live, the wide snapshot is
already retired, the separate pointer vector and first string are zero-initialized
by real calloc, and no nonempty string slot or environment global is published.
This is a precise shared representation limitation, not a malformed fixture or a
claim that x86 cannot execute the code.

The controlled **empty** original-entry variant allocates/returns a one-slot NULL
vector and executes actual stores at0x406a45/0x406a4c to0x41ce54/0x41ce48. It then
executes NULL-free and reaches its temporary-buffer free at0x406a59→0x407d50.
The original **HeapFree import at0x407d66** remains unbound. The valid NULL-only
vector/global stores and temporary buffer remain live; no cleanup or caller
completion is invented. Both entry variants still reject full startup admission.

## Independent checks

Fourteen builder cases cover empty/Unicode/multiple/leading-equals entries,
interior aliases, missing terminators, unknown bytes, scalar addresses without
authority, stale source, changed builder/copy/calloc code, actual zeroed allocation
identities and repeated cleanup rejection. Repeated cleanup uses distinct live
activations; an unbound free never marks its allocation released.

Six original-copy cases isolate the architecture gate. Separate valid heap
allocations reject at the actual SUB. Disjoint byte ranges within one live stack
capability execute the unchanged helper and copy the independently expected bytes.
Numeric-only cancellation computes the right raw address but still cannot access
the other allocation. Stale objects reject. An unknown later source byte preserves
the earlier actual byte store and rejects the unknown control decision. No wider
arithmetic or address-resolution rule was enabled to make these tests pass.

The canonical artifact gate executes both controlled original-entry variants;
all earlier startup, conversion, snapshot-release and frame state remains checked.
All inputs are synthetic. Hidden drive entries appear only as direct builder
component inputs, not as admitted controlled-launch declarations. No real host
environment is acquired or logged, and no new Windows/whole-PE pairs are claimed.
[Hashes and evidence](evidence/environment-table.json).

## Bounded Astra High scope

1. Add a reusable **checked address-relation** contract for the actual numeric
   subtraction/recomposition idiom. Capture source/destination identities and
   live call/arguments; prove original decoded operands and flags. Numeric bits
   alone must continue to grant no dereference authority.
2. Resolve only an actual recomposed read whose address and destination cursor
   match that live relation, selecting the original source capability and bounds.
   Preserve every original load/store, partial write, unknown decision and fault
   order. Do not retag an integer register or globally search mappings by address.
   Expire/revalidate on object retirement, wrong call/context, changed operands,
   aliases, mutation and return/replay. Test unrelated library-like compositions.
3. Reuse the modeled HeapFree ownership/failure/errno contracts to bind an actual
   native owned-heap effect and original free instructions. Do not relabel a
   supplied success observation as native acquisition or assume Windows failure
   cannot occur. Preflight resource/retirement metadata and preserve prior effects.
4. Connect copied-string slot publication, original cleanup0x406b4a, caller
   globals and temporary-buffer retirement together. Prove no string pointer
   aliases the freed temporary. Test allocation/copy failure at multiple entries,
   partial table cleanup, repeated release, stale/reused roots and changed code.

Code boundaries: CrtStreamRuntime::difference rejects different capabilities;
CrtCpu::binary_number intentionally drops authority; CrtCpu::form_address retains
only its checked base capability. Neither a raw-address lookup nor structural
success is an acceptable fix. No complete environment propagation, default
admission, startup/rcedit, exceptional cleanup or resource-failure equivalence
follows from this checkpoint. Historical Windows timeout causes remain unresolved.

Local final validation:351 CRT passes (two artifact gates separately handled),
canonical entry variants/fourteen builder cases, six provenance cases,114 Python
tests(one skip), Clippy warnings denied, formatting and all152 word cases with
512KiB plus64KiB environment padding pass. Independent review compared all553
b6681d9 replay source hashes against exact commit blobs successfully. Final
pushed-head replay and full CI remain separate gates.
