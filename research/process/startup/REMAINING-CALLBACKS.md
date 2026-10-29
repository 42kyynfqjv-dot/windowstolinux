# Remaining native startup/formatter boundaries

This inventory describes the experimental live component path. It grants no
whole-image admission. Addresses are bindings of the retained authored PE, not
application identifiers used to choose behavior.

| Boundary | Current execution | Requirement before removal |
| --- | --- | --- |
| Main report and epilog | Original instructions, live storage, original guard helper, protected CALL/RET and normal-return receipt | Retain original entry/callee contracts and malformed-state rejection |
| printf wrapper, iob and options accessors | Original decoded bodies and actual native CALL/RET; typed FILE/options results bound to owned objects | Keep code/ABI/lifetime checks; do not infer FILE or options initialization from an address |
| stdio-common formatter body | Full-body callback remains for returning cases. Original entry and full locale constructor execute in the rejection experiment | Prove initialized live locale/FILE state, execute driver/parser/integer/output and ordered destruction with correct failure behavior |
| Locale state | Constructor's unknown branch word at0x41ce7c rejects after original object writes | Establish this word and the objects/lifetimes behind0x41c230/0x41c234 from startup/effect evidence; cover alternative/lazy paths or reject them. Image initial bytes and successful samples do not establish post-startup state |
| stdout and options | FILE-array storage is live but stdout fields/lock are unconstructed. Basic options words are explicit initialized component inputs | Prove stream/lock/descriptor/encoding/buffer initialization and mutation assumptions before native formatter access |
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

Next cohesive scope: establish the live locale/FILE domain and connect the full
original formatter driver, parser, integer path, output and cleanup on the shared
owner. Keep raw instruction effects, pointer identity, initialization and failure
order visible in conformance tests. Use the existing helper certificates where
they apply, and reject remaining API/exception effects rather than supply default
results. This is a concrete semantic integration scope suitable for a bounded
Astra High pass after independent Sol review; routine verification stays on Sol.
