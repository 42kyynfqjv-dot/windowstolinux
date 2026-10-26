# SUB-517: typed relocated values and saved ESI

## Decision and status

Design and independent test-only validation. Production `src/` is unchanged;
`linker::Candidate::reject_emission` remains an unconditional barrier. Neither
this model nor structural intake is successful compiler-program translation.
The smallest useful target remains the **unchanged** minimal `compiler/program.c`
MSVC build, not the much larger ordinary CRT build. Review this contract at medium
before implementing its Rust core on Astra High.

## Primary contracts and provenance

- [Microsoft x86 argument passing](https://learn.microsoft.com/en-us/cpp/cpp/argument-passing-and-naming-conventions?view=msvc-170):
  right-to-left stack arguments widened to 32 bits, scalar EAX returns, caller
  cleanup for cdecl, and preservation of ESI/EDI/EBX/EBP when used.
- [Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-block):
  HIGHLOW relocation sites, preferred versus loaded VA and RVA interpretation.
  Structural rules and metadata exclusions remain SUB515/SUB516's responsibility.
- [Intel SDM volume 2, revision 085, October 2024](https://cdrdv2-public.intel.com/835757/325383-sdm-vol-2abcd.pdf):
  ADD pp. 3-32–33, CALL p. 3-139 onward, POP pp. 4-396–400,
  PUSH pp. 4-520–522, RET p. 4-566 onward. Reviewed the instruction descriptions,
  encodings and stack operations: 32-bit pushes decrement ESP by four, pops
  increment it, short immediates sign-extend, CALL/RET use a real stack return
  address, and ADD affects arithmetic flags. The tag abstraction must preserve
  these effects wherever the accepted program can observe them.

Original model/tests are independently authored MIT OR Apache-2.0 code; no Wine,
Intel implementation source or compiler-generated executable is copied into the
repository. The model uses literal observed instruction/relocation facts and
separately specified stack expectations. It is not a clean-room claim.

## Exact observed program

Evidence: commit `ac693627c3f3db7f3d8daf133691df527a292486`, CI
[40271692053](https://github.com/42kyynfqjv-dot/windowstolinux/actions/runs/40271692053),
compiler job 121405685908. MSVC 19.51.36260.0 / LINK 14.51.36260.0.
The unchanged minimal PE SHA256 was
`52dfd367e3939d06e5d8d7408789ac4a39eeae4727b5005e2837f275643ba8aa`.
Rebuild timestamps can change this hash. Preserve the generated artifact within
an experiment; do not patch instructions/relocations or search compiler flags.

| RVA | Bytes / instruction | Required effect |
| --- | --- | --- |
| 1000 | `56` PUSH ESI | Save incoming ESI, including an unknown value |
| 1001 | `6A 05` PUSH 5 | Count |
| 1003 | `68 08 20 40 00` PUSH 402008h | Typed immutable buffer, HIGHLOW at 1004 |
| 1008 | `6A 01` PUSH 1 | Descriptor |
| 100A | `FF 15 00 20 40 00` CALL [402000h] | ImportSlot, HIGHLOW at 100C |
| 1010, 1012 | `6A 05`, `6A 07` | Second helper argument, then first |
| 1014 | `8B F0` MOV ESI,EAX | Preserve `_write` result 5 in ESI |
| 1016 | `E8 25 00 00 00` CALL 1040 | Protected continuation 101B |
| 101B | `83 C4 14` ADD ESP,20 | Remove five argument words; invalidate known flags |
| 101E, 1021 | `83 F8 0C`, `75 09` | Compare EAX with 12, failure at 102C |
| 1023, 1026 | `83 FE 05`, `75 04` | Compare ESI with 5, failure at 102C |
| 1028–102B | `33 C0`, `5E`, `C3` | Return 0 after restoring ESI |
| 102C–1032 | `B8 63 00 00 00`, `5E`, `C3` | Return 99 after restoring ESI |
| 1033–103F | `CC` padding | Unreachable, no relocation sites permitted here |
| 1040 | `8B 44 24 04` MOV EAX,[ESP+4] | Read scalar 7 |
| 1044 | `03 44 24 08` ADD EAX,[ESP+8] | Add scalar 5, compute tracked flags |
| 1048 | `C3` RET | Return scalar 12, leave arguments with caller |

The compiler moved the pure helper after `_write`; do not derive execution order
from the C source. Ordinary Windows baseline: `Hello`, empty stderr, exit 0.
A separate debug-observed launch of the same bytes reported base 0x680000 instead
of preferred 0x400000. Its output/exit also matched. That is **one instrumented
launch**: ordinary baseline load base and relocated operand memory were not read.
Arithmetic samples in the model do not add Windows base observations. Server 2025
is not XP/7 validation. Historical corpus timeout 40269378607 remains unexplained;
subsequent green runs do not establish its cause.

## Value and relocation contract

| Value | Permitted operations | Rejections |
| --- | --- | --- |
| Integer(u32) | Scalar arithmetic/comparison, copies, owned stack data, scalar return | Treating a numeric VA as a pointer |
| Pointer(image identity, immutable RVA) | Identity-preserving copies/save/argument transport; checked `_write` buffer use | Arithmetic, integer casts/comparison, return as EAX, foreign-image use |
| ImportSlot(image identity, IAT RVA) | Exact decoded FF15 call to the one validated import | Register/stack data, general indirect call or memory load |
| Unknown(origin identity) | Opaque copy/save/restore only | Numeric observation, arithmetic/comparison/output/return; equality of different origins |

A proof-owned Rust value must have private constructors and be tied to the
immutable image that validated it. Two images at the same preferred address are
not interchangeable. Numeric equality does not establish provenance. Copies
retain the same image/RVA and unknown origin, rather than reminting either.
Unknown ESI at entry is a symbolic identity, not zero and not a wildcard that
matches every other unknown. Pointer tags must survive stack/call transitions.

Before emission, decode the complete bounded graph (both conditional successors,
all called bodies and continuations), establish nonoverlapping instruction
boundaries, then join **each** live HIGHLOW to exactly one four-byte field of an
allowed reachable instruction. Initial field roles are `68 id` immediate at +1
and `FF 15 disp32` displacement at +2. No prefix/operand-size/address-size variants.
Duplicate sites, instruction-byte/interior overlaps, missing pointer relocations,
extra/unreachable records, wrong-width fields, code/header/metadata targets and
wrong roles reject the whole candidate. Repeated visits to one instruction in
shared call contexts do not duplicate its field record; semantic uses must still
be checked in every context. A scalar immediate without relocation cannot later
become a pointer merely because it resembles an address.

Normalize a validated on-disk preferred VA to an image-owned RVA with checked
arithmetic. ImportSlot identifies the IAT **slot**, never the loader-written
function address or on-disk thunk contents as executable bytes. Buffer use must
recheck its complete count against immutable file-backed nonmetadata bytes,
printable ASCII 0x20–0x7e, count 1–64 and descriptor 1. Revalidate on every reachable
path, including untaken branches and shared callees. No pointer arithmetic or
integer observations means accepted behavior need not reveal the actual base;
this is a proof obligation, not permission to assume relocations have no effect.

## Stack, calls and ABI ownership

Retain one physical-word abstraction, not two unrelated stacks:

- EntryReturn: unique unobservable entry sentinel.
- Data(owner frame, typed value): caller-owned pushed arguments.
- SavedESI(owner frame, typed value): created only by exact PUSH ESI, consumed
  only by matching top-of-stack POP ESI in that owner frame.
- Return(callee frame, continuation): created only by CALL, consumed only by RET.

Each tag occupies four bytes in the abstract guest stack. Save/return tags are
validation restrictions on otherwise ordinary x86 words; a guest cannot create,
inspect or overwrite those tags. PUSH ESI is restricted to preservation, not an
alternative way to construct an argument. POP ESI cannot consume Data or Return.
Cleanup cannot discard SavedESI/Return or another frame's words. Multiple saves
are LIFO; restoring the wrong value fails the final ESI obligation even if the
stack is balanced. No arbitrary stack stores or pointer-to-stack values.

CALL records the callee's incoming ESI and exact continuation in validator frame
metadata; that metadata is **not another guest stack word**. RET verifies ESI
matches the snapshot, then consumes the protected Return. It does not magically
restore ESI. Nested/shared callees have distinct owner/continuation contexts.
Return EAX must be Integer; internal values may span u32, entry return must be
0–255, with only EntryReturn left and original ESI restored on every terminal
path. Other callee-saved registers are untouched because all their uses remain
rejected. Reading ECX/EDX, floating point state or other ABI state is not admitted.

The first two-argument helper gate permits [ESP+4] and [ESP+8] only with the
callee's Return currently on top, and the selected word Data owned by its direct
caller. It does not grant general frame addressing after a prologue. In the
observed helper these words are 7 and 5. Typed argument loads preserve tags;
ADD requires both operands Integer. The `_write` call leaves its three arguments
in place, preserves ESI, returns the full successful count in EAX and makes all
tracked flags unknown. ECX/EDX are volatile/unobservable. Existing regular-file,
CRT startup/byte-mode, errno nonobservation, full-write and failure assumptions
remain those of SUB511/SUB512. This prototype models only the success domain;
it does not test partial-write/errno behavior anew.

`ADD ESP,20` consumes exactly five current-owner Data words atomically, exposing
the saved ESI. It changes CF/ZF/SF/OF based on unknown absolute ESP. Conservatively
mark all tracked flags unknown; reject a branch consuming them before an operation
fully defines them. Do not lower ADD cleanup as flag-preserving LEA. The observed
CMP immediately defines the needed flags. PUSH, POP, MOV and near CALL/RET preserve
tracked flags, excluding the effects of called instructions or external APIs.

Keep flat 32-bit SS/DS, aligned ESP, valid incoming return, 512 accessible bytes
below entry, no wrap/fault/asynchronous mutation assumptions explicit. Headers do
not prove these. At most 128 extra stack words (including saves and transient
external return), 32 nested calls, 1,024 decoded/executed instructions and existing
acyclic forward control flow. No recursion/backward edges, RET immediate, stack
pivot, numeric ESP/return-address observation or general memory.

Joins require exact typed values, unknown identities, flags, stack shape/owners,
frame snapshots and continuations. Otherwise reject or retain separate bounded
contexts; never erase tags to make a join succeed. The first implementation should
use conservative exact joins and bounded existing path handling. Every accepted
terminal path must satisfy ownership/ABI invariants, even if deterministic input
selects only one at runtime.

## Test-only evidence and limits

`tools/typed_abi_model.py` is independent of production and the linker prototype.
Its 16 test functions include 24 concrete byte-stack traces (three sample bases,
four initial ESI integers, two ESPs). Literal expected arguments, continuations,
output and values 5/12 are independent of model operations. A separate byte-addressed
little-endian stack checks push/call/return/cleanup layouts. This is not a general
x86 interpreter: it does not decode the actual PE, execute CMP/JNE, validate PE
metadata, implement runtime errors or compile generated Rust. The success/failure
return paths are explicitly modeled, not derived by executing those branches.

Negative tests cover unknown origin substitution, foreign/unissued pointers,
scalar-pointer confusion, pointer arithmetic/returns, import-as-data, buffer
bounds/bytes, missing/extra/duplicate/wrong-field/wrong-role relocation bindings,
protected/foreign words, unrestored saves, argument positions, cleanup atomicity,
unknown flags, joins/continuations, stack/depth limits and use after terminal RET.
Decoded fields are supplied annotations: tests of a missing annotated successor
are not evidence that a real decoder discovers both successors. Python objects
and mutable test state are not a security boundary. Production needs private
Rust constructors plus actual decoder-derived proofs. The prototype deliberately
leaves arithmetic flags unknown; existing production arithmetic truth tables must
be extended and independently checked during integration.

Reproduce:

```sh
python3 -m unittest discover -s tools -p test_typed_abi_model.py -v
```

Existing evidence stays separately counted: 46 root Rust tests; 43 evaluation
functions including 27 inherited production tests; 15 linker prototype functions;
2,612 CLI rejection attempts; 102 Windows/Linux translated fixture comparisons.
The new 16 functions/24 model traces are not additional Windows/Linux pairs.

## Bounded implementation gates after medium review

1. **Typed core, barrier retained (Astra High):** image-owned values, actual
   decoder-field/HIGHLOW bijection and private proof constructors; ESI save/restore
   tags and call snapshots shared by validator/emitter state. Independently test
   both successors, shared/nested contexts and all negatives above through real
   production paths. No public general register/memory API.
2. **Exact observed ABI forms:** add only `56`, `5E`, `6A ib` (sign-extension),
   `8B F0`, `83 C4 14`, `83 F8 ib`, `83 FE ib`, `33 C0`, `03 44 24 08` plus the
   typed versions of existing forms needed by the trace. No broad ModRM acceptance.
   Test negative prefixes/registers/displacements and immediate boundaries
   0x7f/0x80/0xff. Two-argument ownership and ADD-cleanup flags are separate gates;
   the model's parameterized cleanup is not permission for more production forms.
3. **Emission proof gate:** every graph/context/terminal invariant established,
   exact typed uses validated, output error behavior retained, no numeric pointer
   escapes, native typed data representation and ABI state consistent with
   validation. Prove deterministic generated source; compile without decoder,
   PE loader, Wine or AI runtime. Never route a partially checked Candidate into
   the old scalar emitter. Reject any uncovered requirement before writing output.
4. **Unchanged compiler-artifact comparison:** in one CI experiment preserve PE
   bytes/SHA from the documented MSVC build through Windows baseline, diagnostic
   disassembly/relocations, conversion and Linux execution; require exact `Hello`,
   empty stderr and exit 0. Independently authored failure/negative variants must
   cover both return epilogues and the new forms. Keep the separate actual-base
   observer report, without claiming ordinary-run base or all-base coverage.
   Preserve all 102 prior pairs and ordinary CRT rejection, with no flag search,
   artifact patching or weakening failures. A further instruction discovered in
   fresh compiler output is a reported gap, not implicit authorization to widen.

These are a finite route to one real compiler-produced native program. They are
not a general cdecl/stdcall implementation or application compatibility claim.


## Medium contract review

Review found no reproduced model transition defect or production barrier escape.
Two direct negative assertions now check internal RET rejects clobbered ESI without
consuming its return/frame, and [ESP+8] rejects a physically present SavedESI word
when only one actual argument was pushed. These extend existing functions: the
count remains 16 functions. The 24 concrete traces are parameterizations of one
observed layout scenario, not 24 distinct programs. Only the independent concrete
stack varies numeric load base and incoming ESI; the symbolic model intentionally
retains image-owned RVAs and an opaque ESI identity. Neither is new Windows evidence.
Expected output/7+5/continuations/layout are literal independent expectations;
CMP/JNE execution, real field discovery and arithmetic flag verification remain
production integration gates, as documented above.

Ready for a bounded Astra High production pass. Implement the typed core first
with the barrier retained, then the exact nine observed form groups listed above,
two-word helper accesses and ADD ESP,20 unknown-flag handling. Do not enable the
Candidate emitter until graph-wide field binding, all-context byte/ownership
checks, both balanced epilogues, pointer nonobservation and deterministic native
emission are verified through production tests. Completion requires the same
unmodified MSVC-built PE bytes to run on Windows and translate to a Linux ELF
with Hello/empty stderr/exit0 in one reproducible experiment. If that cannot be
completed within the bounded pass, keep rejection and report the specific gate;
model or decoder acceptance alone is insufficient. Keep ordinary CRT rejection,
all 102 existing comparisons and historical timeout diagnostics. No new register
families, general memory, API coverage or compiler flag search are included.
