# SUB-530: two scalar local words, design only

## Evidence and decision

Target the frozen `compiler/heldout/structure.c` program: a volatile Pair containing
7 and5, whose sum returns12. Inspecting a PE does not authorize this execution.
Production conversion still rejects every held-out case. This change adds an
independent model, tests and exact-artifact evidence check only.

Reviewed unchanged artifact12636732791, CI40293214014, available MSVC19.51.36260.0,
LINK14.51.36260.0. held_structure.exe SHA256
`d2906f2001e8ab81315be777fa66aa7fdfbd8f07cdedf5068782087c04bf3a71`.
Frozen source/configuration cf042295303dccedb8506564f1e466ef9d353acd predates measurement.
Rebuild timestamps change PE hashes; each cross-host run verifies identity, with
no source/flag/binary edits. Windows Server2025 baseline is empty stdout/stderr,
exit12. No imports or relocations, one RX code region and R metadata/data region,
entry RVA1000; debug13 is the only nonempty directory. Preferred base is400000;
this artifact alone supplies no observed-load-base evidence.

| RVA | Exact bytes | Supported operation proposed |
| --- | --- | --- |
|1000|83 EC08|Allocate two uninitialized local words; invalidate tracked flags|
|1003|C7 04 24 imm32|Store scalar immediate at ESP+0 (observed7)|
|100A|C7 44 24 04 imm32|Store scalar immediate at ESP+4 (observed5)|
|1012|8B 44 24 04|Load initialized local word at ESP+4 into EAX|
|1016|03 04 24|Add initialized local word at ESP+0 to scalar EAX|
|1019|83 C408|Release exact owned local allocation; invalidate flags|
|101C|C3|Existing balanced return and scalar exit proof|

Immediate scalar values may vary across the entire u32 domain; addresses/forms may
not. No prefixes, alternate widths/registers/displacements, partial words, indirect
ESP values, arbitrary allocation sizes, byte accesses, heap/global memory or pointers.
Reject near-looking forms explicitly, including address/operand-size overrides,
segment/LOCK/REP prefixes, register-valued stores and [ESP+8] local accesses. Existing
other instruction forms remain separately gated; this is not a general stack model.

## Primary specification provenance

Independent authored implementation, MIT OR Apache-2.0; no Wine source/runtime.
Intel SDM093 Volume2A ADD and Volume2B MOV/SUB/RET contracts:
https://cdrdv2.intel.com/v1/dl/getContent/671199
https://cdrdv2.intel.com/v1/dl/getContent/671241
The web renderer could not open these PDFs in this pass; previously downloaded
primary PDFs/text in the workspace were consulted. ADD/SUB update arithmetic flags;
MOV preserves flags; RET consumes its architectural return address. Microsoft x86
ABI: https://learn.microsoft.com/en-us/cpp/cpp/argument-passing-and-naming-conventions
specifies EAX scalar returns and callee-saved ESI/EDI/EBX/EBP when used. This slice uses
none of the latter except preserving the existing symbolic ESI obligation.

## Representation and valid-execution domain

Retain the existing single tagged word stack, entry sentinel, protected internal
returns, saved-register tags, caller Data arguments and per-invocation owner IDs.
Add `Local(owner, allocation_id, Uninitialized | Integer(u32))`, distinct from Data,
Pointer, Unknown register values, Saved and Return. Numeric bits resembling an address
remain scalar; they cannot become an address/argument pointer. No store of a pointer
or unknown value into a local is authorized. Locals never alias return or saved tags.

Assume a valid aligned Windows stack with at least the bounded accessed storage,
no faults, overflow/wrap, asynchronous mutation or observable stack addresses.
Unknown entry ESP remains unknown. This is a conditional equivalence domain, not
simulation of allocation failure, guard-page behavior, stack probes or exceptions.
An eight-byte decrement reserves storage but does not initialize it. Do not set new
locals to zero merely because Rust needs an initial value: the runtime must retain
a distinct uninitialized tag and reject reads until an explicit store on every path.

One live eight-byte local allocation per invocation. Allocation is permitted only
with that invocation's protected entry/return word at the top, no pending Saved,
Data or Local words above it. Both appended words carry the same fresh allocation
ID/owner; their physical order is high-address slot4 then low-address slot0. Thus
with entry ESP=S, locals occupy[S-8,S-4) and[S-4,S), while the protected entry word
stays at[S,S+4). Abstract bottom-to-top values after stores are[Entry,5,7]. Cleanup
removes exactly the final two local words. Allocation can repeat after cleanup but
gets fresh uninitialized storage; stale initialized contents never survive reuse.

## Transitions, ownership and flags

All bounds/type/ownership/resource checks precede mutation. Failure leaves values,
stack shape, flags and step count unchanged. Tick exactly once per actual instruction.

- Allocate: require balanced current boundary, no live allocation and room for two
  words. Append two Local/Uninitialized tags, set allocation token, invalidate flags.
- Store0/store4: require the complete two-word allocation at top and both words owned
  by this invocation/token. Validate offset0/4 and scalar u32, then replace only that
  slot's value. EAX/flags unchanged. Validate both tags before modifying either.
- Load4: validate the complete frame and initialized scalar slot4; replace EAX only.
- Add0: validate initialized scalar slot0 and scalar EAX; wrap modulo2^32, compute
  CF/ZF/SF/OF from that addition. None of the slot/tag/ownership information changes.
- Cleanup8: validate the exact allocation/token at top; remove both words (they need
  not both have been initialized if never read), clear allocation, invalidate flags.
  No partial cleanup, crossing a protected word, or treating Local as caller Data.
- RET: require no live allocation/pending words, protected return ownership intact,
  callee-saved restoration and initialized scalar EAX. Entry exit remains0..255;
  internal wide scalars retain existing semantics. Returns do not consume flags.

ADD ESP8 already has a caller-Data cleanup meaning in the compiler path. Integration
must dispatch by explicit current-frame allocation state: live locals require the
exact two Local words/token; otherwise only the existing homogeneous owned Data-pair
rule applies. Mixed Local/Data/Saved/Return words reject atomically. Cleanup5/6 and
LEA/Data operations must never erase Local words. Do not pick whichever rule happens
to accept after a failed validation. This overlap is a critical review gate.

SUB ESP8 and ADD ESP8 affect flags based on unknown absolute ESP. Conservatively set
all tracked CF/ZF/SF/OF to unknown. Reject their use until a supported scalar operation
redefines them. Do not compute flags from abstract stack depth. MOV stores/loads
preserve the current known/unknown status; scalar ADD supplies real arithmetic flags.
PF/AF remain unmodeled and any instruction reading them stays unsupported. Existing
valid-stack assumptions may imply some properties, but this contract performs no
such refinement. Prototype literal tests include carry, zero, sign and both signed
overflow boundaries independently of production flag helpers.

## Calls, branches and limits

A direct parameterless call may suspend a complete local allocation below its new
protected Return word. The callee gets a fresh owner and optional fresh allocation;
it cannot access caller locals as Data arguments. Return restores the caller's
context and unchanged local words. Callee register/flag effects remain those of its
actual instructions, not invented preservation. Repeated shared-callee calls cannot
reuse prior local initialization. ESI obligation stays per invocation.

For this extension, prohibit push/save/argument operations or tail transfers while
the current invocation's local allocation is live. Cleaned invocations may use old
forms under their old checks. Allocation above pending saved/Data words also rejects.
Do not expand ordinary argument/caller-write authority to include Local words. Existing
programs without locals retain their old behavior. Static routine ownership and
acyclic call/tail graph proof remain prerequisites; the prototype's active-call
recursion check is only a model guard, not a replacement for whole-graph validation.

Keep branch states separate through joins, including initialization, allocation ID,
owner, frame shape, scalar values and flags. A write on one path cannot initialize
another. Validate both successors including untaken paths. No intersection/union
shortcut may erase a rejection. Clone state for exploration, retain original return
contexts and validate each path independently before constructing a proven program.

Retain129 total tagged words,32 internal calls,1024 instructions per path,1024 decoded
instructions and4096 explored states. The last two are graph-validator responsibilities,
not implemented by the action-only prototype. Entry+32 nested two-local frames and
returns fit below129; mixed existing operations still need the global cap. Boundary
and atomic-failure tests must exercise caps at production integration. No backward
loop or arbitrary recursion support is implied.

## Minimal intake-to-execution gate

Do not expose an emitter method on inspection Envelope or deserialize its JSON into
an executable object. Add a private checked conversion view only after:

1. Owned snapshot passes reviewed layout/range/permission checks; one RX code region,
   remaining regions immutable and all program/code widths file-backed. No writable,
   zero-fill, discardable execution, unsupported architecture/subsystem/flags.
2. Directories are absent except optional existing bounded debug13, whose full
   transitive payload is reserved. No import/IAT/relocation, TLS, load-config, exception,
   certificate, bound/delay import or other startup obligation. Metadata closure must
   be validated from bytes; a supplied Boolean/report cannot establish it.
3. Entry and all reachable instruction bytes stay in code, outside metadata. Decoder
   accepts only reviewed exact forms. New path permits register/local scalar semantics
   plus existing bounded direct control flow; exclude all absolute data/IAT/pointer
   forms in the initial importless view. No relocation directory plus DYNAMIC_BASE
   does not prove preferred load address. Without address observation/absolute operands,
   this slice must be base-independent by instruction proof, under the stated stack domain.
4. Existing graph/resource/flags/register/return proof and new local-word proof succeed
   on every path. Only a private proven-program constructor can authorize Rust emission.
   Runtime and validator use the same checked transitions after independent semantic tests.

Keep old authored and strict imported compiler profiles intact. New semantic view
selection must validate its own predicates; no catch-all retry that hides malformed
metadata from another parser. Select profile explicitly from validated header/directory
facts and reject ambiguities. Support debug-bearing, importless images because of
validated metadata semantics, not a special filename/hash/exact-section-count exception.
The frozen structure artifact is an acceptance fixture, not an input allowlist.

## Prototype and implementation acceptance

`tools/local_frame_model.py` imports no production/old-model helpers. Nine test
functions contain literal stack layouts, arithmetic flag tables and independent
positive/negative traces: exact seven-instruction exit12, partial initialization,
misaligned/cross-boundary words, forged protected/foreign tags, pointer/unknown values,
nested/shared calls, path-local initialization, cleanup/reallocation, ESI/exit bounds,
step/depth/recursion/terminal checks. The model assumes decoded actions and valid
static graph; it is not a PE parser, x86 decoder or native execution result.

`tools/check_local_frame_contract.py` verifies the unchanged compiler artifact hash,
frozen source hash, exact independently recorded29 code bytes and Windows baseline,
then runs the literal action trace and requires12. Windows and Linux CI both run this
check on the same artifact. It explicitly requires production conversion still rejected.
This links the proposed contract to observed instructions, not a translation claim.
Earlier eight compiler comparisons,102 authored comparisons,18 launches and all held-out
rejections remain mandatory. No retries or timeout thresholds change. Three historical
original-Windows timeout causes remain unresolved; persistent evidence capture remains.

After medium contract review, a bounded Astra implementation must add only these
forms/local transitions and checked importless execution view, with independent native
boundary cases and production negatives for every listed gate. Test mixed Data/Local
cleanup specifically, both branches, nested/shared calls, uninitialized reads, full
word bounds, protected tags, ESI/exit/flags and limits. Require actual unchanged MSVC
PE->Rust->ELF empty stdout/stderr/exit12 on both OSes, matching source/PE hashes and
byte-identical generated Rust across conversion hosts. Keep other held-out cases
explicitly rejected unless separately authorized/proven. No binary edits, compiler
flag cherry-picking, heap/global/byte-memory, CRT, loop or PE32+ scope expansion.

Medium handoff: audit frame allocation ordering, cleanup opcode overlap with Data,
unknown ESP flags, all-path initialization, inter-invocation ownership and the private
intake promotion predicates. Resolve any substantive mismatch before implementing.
No external-resource blocker is known. Evidence is Windows Server2025 only; XP/7 and
ordinary application compatibility remain unvalidated. No merge/release.

## Medium contract review

The initial prototype exercised only local cleanup although the contract required
explicit local-versus-Data dispatch. The reviewed model now selects solely from
current invocation allocation state. Live allocation validates both Local words and
token; no live allocation requires two trailing owned Data words above the protected
boundary and rejects any untracked Local in the current frame. A failed Local check
never falls through to Data cleanup. This is a test-only validation gap correction,
not additional production support. Data values are discarded without reinterpretation;
existing pointer-valued Data cleanup does not imply permission to store pointers locally.

Added a tenth independent test function for successful Data cleanup and atomic
rejection of live-local/Data substitutions, mixed slots, protected Saved/Return,
foreign ownership, untracked Local and crossing the entry boundary. Local windows
also validate the actual protected boundary tag/owner before writes/cleanup; malformed
boundary substitution now rejects immediately. Prior nine tests retain initialization,
unknown ESP flags, bounds, nested/shared calls, joins and exact seven-instruction trace.
Production remains unchanged and all eight held-out conversions must still reject.

Intake review confirms the proposed promotion remains private and requires fresh
validation from the same owned snapshot, supported directory closure and full graph/
ABI/stack proof; an inspection report or caller-supplied Boolean has no authority.
The prototype takes decoded actions, so prefix/width rejection and graph exploration
limits remain production gates, not model evidence. The exact-artifact checker pins
literal observed code bytes and frozen source/PE hashes independently of the model;
its exit12 trace is not native translated execution. SUB-531 must test both cleanup
modes, failed-mode no-fallback, tag/owner/token mismatches and preservation of all
protected words through the real validator and emitted runtime before acceptance.
After this review the bounded Astra implementation is ready under those gates.
Three historical original-Windows timeout causes remain unresolved.
