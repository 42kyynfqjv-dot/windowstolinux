# Remaining native startup/formatter boundaries

This inventory describes the experimental live component path. It grants no
whole-image admission. Addresses are bindings of the retained authored PE, not
application identifiers used to choose behavior.

| Boundary | Current execution | Requirement before removal |
| --- | --- | --- |
| Main report and epilog | Original instructions, live storage, original guard helper, protected CALL/RET and normal-return receipt | Retain original entry/callee contracts and malformed-state rejection |
| printf wrapper, iob and options accessors | Original decoded bodies and actual native CALL/RET; typed FILE/options results bound to owned objects | Keep code/ABI/lifetime checks; do not infer FILE or options initialization from an address |
| stdio-common formatter body | Full-body callback remains for returning cases. Original entry and full locale constructor execute in the rejection experiment | Prove initialized live locale/FILE state, execute driver/parser/integer/output and ordered destruction with correct failure behavior |
| Locale state | Constructor's unknown branch word at0x41ce7c rejects after original object writes. Lifecycle tokens now bind runtime identity as well as thread/generation; they do not initialize locale data | Establish this word and the objects/lifetimes behind0x41c230/0x41c234 from startup/effect evidence; cover alternative/lazy paths or reject them. Image initial bytes and successful samples do not establish post-startup state |
| stdout and options | FILE-array storage is live but the connected printf stdout fields/lock are unconstructed. The separate original initializer now uses a result-aware lock transition: only API success grants ownership, and constructed lock bytes are opaque. Basic options words are explicit initialized component inputs | Prove stream/lock/descriptor/encoding/buffer initialization and mutation assumptions before native formatter access |
| Inherited startup records | Original parser feeds the original standard-handle body on the same typed owner; seven native cases cover valid/empty input and bounds/lifetime/provenance failures | GetStartupInfoW output and already-provisioned descriptor capacity remain explicit effects. Bind the real allocator/block-lock/inheritance lifetime before claiming startup; reserved-data protocol is derived from original instructions |
| Standard-handle low-I/O initialization | Original 176-byte body executes in 25 native component cases with explicit API outcomes and pre-owned records. Artifact bytes/imports are bound; inherited handles, detached sentinels and type flags follow original instructions | Bind preceding block allocation/inherited startup data, actual API acquisition and handle lifetime/alias contracts, then connect resulting records to FILE startup. No initialized record or full startup authority follows from these tests |
| Integer C++ record and cleanup | Separate instruction/metadata inventory and partial helper proofs; no complete dispatch equivalence | Preserve the original C++ record/handler semantics or prove a complete contained domain. An EH4 token cannot stand in for this record |
| Output backend and exit | Separate writer/FILE/error/flush components exist; this connected path makes no physical stdout claim | Bind native formatter output to those effects; test short writes, errors, buffered flush/close and termination order |
| Original outer invocation and startup | Some outer-frame scalar state remains explicit entry input | Execute the original caller/initialization effects and module/thread entry; do not supply expected report arguments as execution |
| Windows exception delivery and unwind | Captured/delivery objects, incoming-chain containment and some API effects remain bounded component premises | Close actual acquisition and RtlUnwind/collided effects for each admitted domain; reject incomplete paths before program emission |

The returning printf tests still provide a native formatter result and validate
actual options/FILE/format/varargs routing. They do not format text. A separate
experiment executes original formatter entry and constructor instructions until
an unknown locale-state read; it cannot produce a successful return. Neither
experiment is a new Windows/ELF stdout comparison. Actual-load-base and historical
Windows process-exit timeout limitations remain unchanged.

The artifact-bound `locale_state_evidence` in `formatter_binding.py` and the
cross-host wrapper report now preserve a concrete mutation hazard. The branch
word is four virtual zero-fill bytes; the two pointer cells have file-backed
initial address integers. A conditional CALL at `40b2f8` reaches `407126`, which
exchanges scalar one into the branch word. A separate conditional path ending at
`40b372` writes through an object into the multibyte-info cell. This is **static
effect evidence**, not proof that either path executes during startup or an
exhaustive writer/alias inventory. Neither immutable globals nor nonzero state
may be assumed from these findings.

The next implementation must discharge these specific producer obligations:

1. Bind loader/module data and relocation-derived pointer cells to actual live
   locale objects and complete initialized ranges. Prove relevant startup and
   external-call effects, plus exclusion or handling of later mutation.
2. Bind FILE construction and its exact lock/descriptor state to the original
   initialization instructions. The lifecycle proof still exposes allocation,
   lock construction and low-I/O effects. The checked lock-result adapter consumes an external outcome and does not prove the OS invocation or low-I/O startup; creating storage or ending an
   initialization token does not discharge them.
3. Compose the driver/parser/integer/output and ordered cleanup on that same
   owner, including PTD errno/doserrno and temporary locale-state release on
   failure. Preserve the distinct C++ record and invalid-parameter/termination
   paths. Unsupported domains must reject before program emission.

The retained Windows observer records stream/write/lock/return boundaries, not
the complete locale object graph. It cannot certify those missing producer or
lifetime facts. Independent state/mutation/failure cases and original-instruction
execution are required; supplying zero globals or a "C locale" marker is not a
valid substitute. A bounded Astra High pass is warranted for this connected
producer/effect composition; routine regression and evidence checks remain on Sol.

Next cohesive scope: establish the live locale/FILE domain and connect the full
original formatter driver, parser, integer path, output and cleanup on the shared
owner. Keep raw instruction effects, pointer identity, initialization and failure
order visible in conformance tests. Use the existing helper certificates where
they apply, and reject remaining API/exception effects rather than supply default
results. This is a concrete semantic integration scope suitable for a bounded
Astra High pass after independent Sol review; routine verification stays on Sol.

Current concrete allocator integration: `40bf2a` calls the `40be7a` block
constructor. Its 64 descriptor records have stride 56 and critical sections at
record offset 0, while FILE locks use offset 32. Checked typed allocation issuance and distinct record-lock ownership now execute
with original constructor/destructor instructions, followed by the inherited and
standard-handle bodies in native component tests. No existing Buffer alias is
relabelled. The original manager's allocation loop and normal cleanup funclet now
execute on an owned component frame: lock 7 precedes scope activation, blocks and
capacity publish in original order, and scope -2 precedes cleanup release. Distinct
module-global leases preserve partial effects on acquisition/release failures.
The actual EH4 prolog/registration/epilog, exception-driven cleanup invocation,
Enter/Leave helper instructions and producer invocation remain to connect.
calloc/new-handler/errno (`407cf0`), free failure/errno (`407d50`), and continuation
after failed critical-section initialization remain unresolved. Explicit inputs
include global-lock initialization, frame/request, allocator availability and API
outcomes. Next: bind manager EH4 and invoke it from the inherited producer on the
same owner, then continue locale/FILE production. Sol can proceed; escalate only a
concrete missing exception-effect contract. Full startup/formatter/rcedit remains
unsupported until unchanged-binary entry-to-exit evidence passes.
