# SUB-543: isolated native Rust sentinel effect

`examples/crt_sentinel.rs` implements only the local initialization operation in
[the reviewed contract](ONEXIT-STATE-DESIGN.md). Production decoding, conversion
eligibility and ordinary CRT rejection are unchanged. A successful research result
always reports `prior_effects_closed`, `complete_startup_proof` and
`emission_allowed` as false.

## Binding and authority

The immutable snapshot owns its bytes and initialization map. A private `Bound`
borrows exactly that snapshot; no operation accepts another image or arbitrary
pointer. The result is a value describing ordered writes, not an applied mutation
or a transferable write capability. A prior unknown external effect or missing
exclusive, disjoint, valid/fault-free stack premise prevents binding. The CLI
constructs an explicitly isolated research premise, never a certificate of actual
state after preceding startup calls.

Checked PE32/base/section profiles, file and virtual ranges, permissions, complete
backing, section aliases, directories and HIGHLOW records constrain the snapshot.
The full helper 0x13e0, query 0x1c60, failure body 0x17c0, registration wrapper 0x15c0,
caller window 0x104f and initializer pointer 0x20c8 must match the reviewed bytes.
All absolute operands require relocations; extra overlapping code relocations
reject. Full regions are mode [0x3098,0x309c), flag [0x30a9,0x30aa) and two adjacent,
disjoint twelve-byte tables [0x30ac,0x30b8), [0x30b8,0x30c4). Their addresses are
fixed by code, never supplied as effect arguments. TLS/unsupported directories,
metadata in writable data, code/header/zero-fill aliases and altered addresses
reject. The entire declared 192-byte load config is checked even though its data
directory size is only 64. Its cookie pointer and metadata tail are bound, with
required pointer relocations; they grant no startup/cookie implementation.

Known relocated pointers starting inside these regions must be exact admitted
operands. This is not a whole-program alias proof: pointers starting outside may
reach them via arithmetic, and foreign/non-relocated pointers remain unresolved.
Isolation from those aliases, concurrent writes and outside effects is an explicit
assumption. In particular the earlier `__p__commode` write remains unclosed.

All snapshot bytes except the 24 overwritten table bytes must be known. Thus even
an early return conservatively requires known mode and valid complete table backing.
Unknown table contents may be overwritten, but never grant ownership. On an early
return they remain unknown and are reported as `??`, without reading invented zeros.
The research component has no opaque CRT table/allocation lifecycle authority.

## Exact effects

A known nonzero flag takes the early path before policy validation: AL becomes1,
upper EAX bits and their knowledge are preserved, and there are no image writes.
CMP byte flag,0 sets CF=OF=AF=0, ZF=0, SF from bit7, PF from byte parity. Other
arithmetic flags are reported explicitly; unrelated flags are preserved by this
local sequence. ESI is untouched and only EBP is saved/restored.

A zero flag requires policy exactly1, including when mode is0. Policy0, unknown
policy and fast-fail policies reject; none silently fall back to sentinel success.
The query reads the initialized mode and clears upper EAX. Six four-byte FFFFFFFF
stores precede the flag-byte1 store, and EAX ends at1. For mode0 final TEST EAX
sets PF=ZF=1; for nonzero mode final TEST ESI (policy1) clears PF/ZF. Both clear
CF/OF/SF and leave AF undefined. MOV stores, POPs and RET preserve those flags.

EBX/ECX/EDX/ESI/EDI/EBP are preserved, EIP returns, and final ESP is entry ESP+4.
The incoming argument remains caller-owned. Peak stack below helper entry is4bytes
on the early path or12bytes while EBP, ESI and the query return word are saved.
Protected return/saved words are inaccessible to the image effect. No numeric ESP,
return-address bytes, stack overflow or fault equivalence is invented. Exact bound
code justifies this conditional stack calculation; CPU probes check balanced return
and EBP/ESI/ECX/EDX preservation but do not measure the peak.

Rust uses u8/u32 and canonical known-bit masks. Text boundaries accept decimal
unsigned integers only, rejecting fractional/negative/oversized representations.
Unknown bits are represented by value0 with a cleared knowledge bit, never as known0.

## Independent evidence and reproduction

- `cargo test --locked --example crt_sentinel`: 14 new Rust test functions. The
  authored PE-shaped structural fixture is not a runnable Windows program. Binding
  literals construct the premise; semantic assertions independently specify ordered
  bytes, flags and known masks. Includes272 single-byte binding corruptions and
  11,264 truncations as subcases, not extra test functions.
- `python research/crt/check_sentinel.py EVIDENCE --windows-probe`: same unchanged
  held_crt PE and manifest hash, eight literal vectors, fourteen malformed CLI
  scenarios, and an independently authored CPU probe built `/W4 /WX /O2` with MSVC.
  Inputs are synthetic in-memory overlays; the compiler artifact is never edited.
- `python3 research/crt/check_sentinel.py EVIDENCE --compare`: same PE, source/spec
  hashes, deterministic Rust reports and CPU binary hash. Eleven CPU observations
  cover eight vectors; unknown upper bits use two concrete representatives and only
  compare known output bits. That is supporting evidence, not proof by sampling;
  the AL mask rule and independent Rust unknown-bit tests establish the abstraction.

The CPU probe operates on authored local globals and a scoped call/return helper,
never copied PE code. It independently executes CMP/MOV/TEST/XOR/SETNE and six
stores; it excludes external initialization and failure paths. Expected outputs are
literal JSON, not derived from Rust, production decoder or original fixture builder.
Raw stdout, stderr, exit and probe/source/PE hashes are retained. Defined flag masks
exclude AF after TEST; early CMP's defined AF=0 is checked separately.

Primary contracts: Intel SDM volume2 CMP/TEST/MOV/XOR/SETcc/PUSH/POP/CALL/RET,
https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html ;
Microsoft PE format https://learn.microsoft.com/en-us/windows/win32/debug/pe-format ;
MSVC inline assembler https://learn.microsoft.com/en-us/cpp/assembler/inline/inline-assembler .
The source is independently authored under MIT OR Apache-2.0, with no Wine or CRT
implementation source import. The existing onexit lifecycle/dispatch probes remain
separate evidence; their success does not prove external failure or alias behavior.

## Remaining gate and review

Medium review should audit byte/profile and relocation binding, scoped known state,
mask/flag semantics, write order, stack assumptions and actual CPU artifacts. Keep
12 compiler comparisons,102 authored comparisons,18 launch diagnostics and four
held-out rejections separate from isolated probes. Windows Server2025 does not
establish XP/7 support, and three historical Windows timeout causes remain unresolved.

The next useful startup closure gate is the earlier `__p__commode` returned-pointer
write: establish actual pointer ownership, lifetime, aliases and effect boundaries
before composing this component with callback0x1030. That requires a bounded Astra
analysis/probe contract, not assuming the process-global CRT pointer belongs to
this image. Later `_crt_atexit` registration, heap/failure/callback effects and full
startup remain separate blockers. This component alone enables no new program.
