# SUB-532: one owned byte-local word, design only

Frozen buffer.c writes65 and66, increments the latter to67 and returns132. The
unchanged MSVC19.51.36260.0/LINK14.51.36260.0 PE contains exactly34 entry bytes:
`51 c6042441 c644240142 0fb6442401 fec0 88442401 0fb64c2401 0fb60424 03c1 59 c3`.
Original Windows Server2025 baseline: empty stdout/stderr,exit132. Source/configuration
freeze cf042295303dccedb8506564f1e466ef9d353acd remains untouched. Production rejects
at PUSH ECX. This proposal adds test-only design evidence, not executable support.

## Primary specification and exact forms

Independent authored model/specification, MIT OR Apache-2.0; no Wine source reuse.
Intel SDM093 Volume2A INC and Volume2B PUSH/POP/MOV/MOVZX contracts were read from
previously downloaded primary PDFs/text in this workspace (web PDF renderer had
failed in earlier design work):
https://cdrdv2.intel.com/v1/dl/getContent/671199
https://cdrdv2.intel.com/v1/dl/getContent/671241
INC preserves CF and updates OF/SF/ZF/AF/PF for operand width. MOVZX zero extends;
MOV/MOVZX/PUSH/POP preserve arithmetic flags. PUSH stores the source after decrement;
POP loads the current contents before increment. Microsoft x86 ABI source:
https://learn.microsoft.com/en-us/cpp/cpp/argument-passing-and-naming-conventions
ECX is volatile; it need not equal its entry value at return. ESI obligations remain
as already implemented. Neither a valid stack nor an initial ESP value is proven by
instruction bytes; preserve sufficient aligned storage/no-fault/no-wrap/no-async domain.

| Encoding | Proposed exact operation |
| --- | --- |
|51|PUSH ECX: reserve one owned four-byte cell containing ECX bytes|
|C60424 ib|Store scalar byte at ESP+0|
|C6442401 ib|Store scalar byte at ESP+1|
|0FB6442401|MOVZX EAX,byte[ESP+1]|
|FEC0|INC AL; preserve upper24 EAX bits and CF|
|88442401|Store AL at ESP+1|
|0FB64C2401|MOVZX ECX,byte[ESP+1]|
|0FB60424|MOVZX EAX,byte[ESP]|
|03C1|Existing full scalar EAX+ECX|
|59|POP ECX: load current four bytes and release cell|
|C3|Existing balanced scalar return|

Immediate bytes may vary0..255. No prefixes, other registers, displacement sizes,
offsets2/3, widths, register-indirect general memory, arbitrary POP or byte argument
access. Addressing offsets0/1 still require whole owned four-byte cell. Exact observed
forms are the future decoder gate; this action model does not decode x86.

## Byte and register representation

Add distinct ByteLocal(owner,allocation,[Byte;4]) beside existing Local/Data/Saved/
Return/Entry tags. A Byte is Known(u8) or Unknown; it is not an address/pointer tag.
Little endian indices0..3 represent increasing memory addresses. PUSH ECX copies its
scalar bytes, including unknown bytes, into the cell. It does not initialize unknown
bits to zero. Typed pointers must reject at this boundary. Original example evolves
[?,?,?,?] -> [65,?,?,?] -> [65,66,?,?] -> [65,67,?,?].

Registers EAX/ECX require a scalar partial-byte representation alongside existing
Integer/Pointer/Unknown provenance. All known bytes can normalize to Integer. Partial
scalar bytes must never manufacture Pointer provenance or equal symbolic unknown
identities used for saved-ESI proof. Existing full scalar consumers (arithmetic,
comparisons, arguments/output, RET) reject any unknown byte. Existing operations
moving values into ESI or caller Data must reject partial scalars initially; allowing
them would require a separately checked extension. Existing unknown full-register
origins/saved equality remain intact. This integration is a required implementation
gate, not code supplied by the prototype.

INC AL requires a known low byte only, changes that byte modulo256, and preserves
the other three byte states exactly. Thus [255,?,AB,CD] becomes [0,?,AB,CD]; full EAX
use still rejects. Store AL needs only known AL. MOVZX reads a known memory byte and
replaces the entire destination with [byte,0,0,0], discarding previous upper unknowns.
POP ECX reads all four cell bytes, including unknowns, and replaces ECX with that
partial scalar. It does not restore a saved register and cannot simply discard the
load: later full ECX arithmetic must reject until known/reset. In the frozen trace,
POP yields [65,67,?,?], while EAX already holds132 and is the sole returned value.

## Ownership, access and cleanup

One live ByteLocal per invocation, allocated only at its balanced protected Entry/
Return boundary. No pending Data/Saved/Local or other allocation. ByteLocal and the
existing two-word Local allocation are mutually exclusive. Allocation tokens fresh
per invocation/allocation; no previous-cell initialization survives a new PUSH except
the real byte contents copied from current ECX.

Validate boundary tag/owner, live allocation kind/token, complete cell shape and every
byte type before access or cleanup. Byte writes replace exactly one byte; repeated
writes are last-write-wins without touching neighbors. No word read/write may reinterpret
a ByteLocal as Data or Local, and byte reads/writes may not reinterpret those tags.
This excludes overlapping-width aliases and crossing protected slots, rather than
silently choosing a view. POP59 consumes only the exact current owned ByteLocal.
ADD ESP8/20/24 and old LEA/Data cleanup must reject it without fallback. No general
PUSH ECX data/saved-register semantics are admitted by this allocation form.

A parameterless direct call may suspend ByteLocal below a new protected Return;
the callee has a fresh owner and may allocate its own cell. Caller bytes cannot be
borrowed as arguments. Push/save/argument/output/tail operations with active byte
locals reject; return requires cleanup. Joins keep separate byte initialization,
ownership, allocation and register/flag states; validate both branch successors even
when only one is concretely taken. All checks precede committed mutation, including
PC and step count. Existing ESI and bounded-exit obligations apply.

## Flags and resources

INC AL sets ZF=(newbyte==0), SF=bit7(newbyte), OF=(oldbyte==127); CF retains its known
or unknown state. PF/AF have real architectural effects but remain unsupported to
read. The existing Option<Flags> cannot precisely represent unknown CF with known
ZF/SF/OF. Proposed integration uses independently optional tracked flags and audits
all consumers: each condition requires only its inputs; signed comparisons require
both SF/OF. Whole-scalar ADD redefines all four. PUSH/POP and byte MOV/MOVZX preserve
flags, unlike ADD/SUB ESP. Never derive flags from abstract stack depth or mark unknown
CF clear after INC. No new branch forms are proposed.

Keep129 total words,32 internal calls,1024 steps per path/decoded instructions and4096
explored states. The prototype checks step/depth/storage transition limits but does
not decode or prove graph acyclicity, execute ESI transitions or implement all legacy
operations. Those remain production integration requirements. Unknown bytes are
conservative abstractions, not arbitrary invented runtime input values.

## Evidence and next gates

Eight independent model test functions use literal concrete layouts, original-source
arithmetic132, byte/32-bit arithmetic boundary tables, unknown upper-byte cases,
protected/foreign/mixed tags, repeated overwrite, MOVZX, POP partial values, nested/
shared calls, path initialization, cleanup/limits and atomic rejection. No imports
from production, old models or fixture generators. tools/check_byte_local_contract.py
checks frozen source hash, unchanged PE hash, literal34 code bytes and independently
recorded Windows baseline before the decoded-action trace. Windows and Linux run it
on the same compiler artifact. Its model exit132 is explicitly separate from production
conversion, which must still reject. Nine existing compiler comparisons,102 authored
pairs,18 launch samples and seven held-out rejections remain required.

Medium review must resolve partial-scalar integration with existing typed values,
per-flag migration, PUSH/POP ownership and exact form restrictions. The smallest
subsequent implementation adds only the table above with unified checked runtime/
validator transitions and private importless intake already established. Require
independent production negative/native boundary tests and actual unchanged held_buffer
PE->Rust->ELF empty stdout/stderr/exit132 with same source/PE/Rust provenance. Change
conversion acceptance separately from frozen sources/flags. Other six held-out
capabilities remain rejected. No writable globals, heap/general memory, loops, CRT,
PE32+ or load-base assumption expansion. No known external resource blocker.
Three historical Windows timeouts remain unexplained. Windows Server2025 evidence
alone does not establish XP/7 or general application compatibility. Draft/unmerged.

## Medium contract review

Added a ninth independent test function: known AL with unknown upper EAX bytes can
be incremented/stored; full reads still reject. POP followed by PUSH without an ECX
reset copies the modified partial value, retaining the known overwritten byte and
unknown neighbors. The previous fresh-storage test intentionally reset ECX; it did
not cover this real reuse path. MOVZX and cleanup preserve flags throughout. No
production change or reproduced production defect.

Knowledge is whole-byte Known/Unknown, not arbitrary bit masks. A partly known byte
is conservatively Unknown. No unsupported operation may refine it into a known byte.
Partial values must normalize to ordinary Integer only when all four bytes are known;
low-byte access to an opaque full-register Unknown remains unknown unless a supported
operation established that byte. Numeric scalar bytes cannot confer pointer authority.
Audit each existing scalar consumer and symbolic ESI preservation independently.

Ready for bounded SUB-533 Astra implementation after this review: exact compiled
forms, distinct allocation-kind dispatch, partial EAX/ECX scalar state and independently
known tracked flags; every legacy instruction consumer must retain conservative
unknown/pointer/ownership checks. Production must test modified POP/PUSH reuse and
known-AL/unknown-upper stores, flag-specific unknown reads, byte/word alias rejection
and both allocation kinds through shared validator/emitted transitions. Prototype
action tests do not prove prefix decoding or full graph/ABI behavior. Require actual
unchanged hashed buffer PE->Rust->ELF exit132; retain other six held-out rejection
gates and all earlier evidence. Three historical timeout causes remain unresolved.
