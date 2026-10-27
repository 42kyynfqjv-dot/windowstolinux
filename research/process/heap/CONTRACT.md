# SUB-577 shared default-heap effects — bounded component

This slice implements allocation/free/resize effects in the **same numeric-address
Space** used by generated streaming frames. It does not yet bind Heap imports or
admit heap programs. The two frozen compiler programs must still reject. A native
Rust component comparison is not a PE-to-Rust-to-ELF comparison.

## Primary contracts and independent implementation

Requirements were read on 2026-10-27 from Microsoft's
[GetProcessHeap](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-getprocessheap),
[HeapAlloc](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc),
[HeapReAlloc](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heaprealloc),
and [HeapFree](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapfree)
contracts. Original implementation and authored fixtures: MIT OR Apache-2.0; no
Wine/CRT implementation source was imported. This is not a clean-room claim.

The selected documented effects are positive-size allocations with flags 0 or
HEAP_ZERO_MEMORY, successful free with flags 0, and positive-size resize with
flags 0 or HEAP_ZERO_MEMORY. PE32 alignment is eight bytes. Resizing preserves the
common prefix; zeroing applies only to newly added bytes. An allocation failure
returns NULL; failed resize retains the old object. HeapAlloc/HeapReAlloc failure
does not set LastError. Success LastError values are not specified here.

The implementation rejects zero-size requests, null free/realloc, other flags,
private heaps, invalid/interior/freed pointers and unresolved effects. In-place-only,
exception-generation, HeapCreate/Destroy, concurrent access, allocator metadata,
slack bytes beyond requested size and Windows fault/SEH behavior are not implemented.
A documented nullable HeapFree parameter is not interpreted as an inferred success
rule. Invalid-original-memory accesses are never executed as Windows fixtures.

## State and failure boundary

`ProcessHeap` is an opaque host-side process proof token, stable within a Space;
it is **not** a guest HANDLE encoding. Cross-process tokens reject even if numeric
allocation addresses coincide. Only regions created by the heap adapter are API
allocations; merely mapping Owner::Heap(0) cannot create one. Existing trusted core
mapping primitives retain their own authority, not an ordinary guest callable API.

Allocated pointers are numeric PE32 VAs, aligned first-fit within a selected
0x10000000..0x20000000 arena, respecting all existing mappings. This is a native
layout choice, not a measured or promised Windows address. Address-oblivious byte
effects can be compared; printed pointer bits, pointer ordering across allocations,
move/no-move observations or allocator-address-dependent control require additional
proof/layout assumptions before translation. A token/generation never replaces
pointer bits in memory or a register.

Storage tracks requested extents and byte-definedness. Uninitialized allocations
have inaccessible unknown bytes, even though backing storage is physically zeroed.
Resize constructs a replacement before committing: prefix bytes and definedness
survive; only a zero-requested new tail is defined. A new generation invalidates old
proofs even for same-address resize. Free invalidates capabilities. Raw numeric
addresses can alias a subsequent allocation at the same address; stale proof tokens
still reject. Original undefined/dangling-pointer programs are outside admission.

Host allocation errors, counter overflow, arena exhaustion, the inherited 64-region
or 1-MiB logical limit return an explicit component error. They **never become a
fabricated Windows NULL or exception**. Replacement peak backing storage is bounded
by old plus new, with separate definedness storage. `Availability::AllocationFailed`
is a trusted, explicitly injected conformance outcome: after request/identity/base
validation it returns None without mutation. It does not predict Windows exhaustion,
allow guest code to choose allocation success, or establish resource equivalence.
No huge allocations are used to force Windows failure.

There is no thread LastError state in this component. An eventual API binding must
preserve it on injected Alloc/ReAlloc failure, invalidate knowledge on unspecified
success effects, and separately justify GetProcessHeap/HeapFree failure handling.
Call-clobbered registers/flags and stdcall cleanup also remain binding obligations.
No hidden external mutation, callbacks, asynchronous access or other heap user is
assumed within this bounded component; those effects prevent admission until modeled.

## Evidence categories

- Ten independent Rust test functions (literal bytes/invalid transitions) added to
  138 inherited root tests. Five guard/copy-omission mutations reuse those tests;
  they are not five additional test functions. Existing seven memory tests and
  seven mutation checks remain, with ten emitted-frame vectors.
- Two structurally different custom-entry C programs and 16 independent cases per
  program were frozen at f188f69 before converter measurement. `grow` fills a
  runtime-sized block and appends a zeroed tail. `shrink` shrinks one block, reverses
  its prefix into a second block and frees the first before output. Flags are fixed
  ordinary MSVC /O2 with explicit freestanding assumptions; no binary edits.
- Windows harness records toolchain/source/PE hashes, exact bytes/exits, headers,
  imports and disassembly. 32 success observations and four real I/O failures are
  required. Allocation success in these small probes does not prove OOM behavior.
- `examples/heap_effects.rs` calls the actual shared component and compares 32
  outputs to independent expectations and Windows observations. It is separately
  authored Rust, **not generated Rust**. The two unmodified PEs are queried on both
  hosts and must reject consistently without overwriting the output file.
- Actual completed results and CI belong in RESULTS.md; intended counts here are
  acceptance criteria. Modern Windows evidence does not validate XP/7.

## Concrete remaining integration gate

Inspection found a structural barrier, not just missing API names:
`src/linker/stream/frame.rs::Value` has only frame provenance, and `State::address`
requires a frame base. Pointer stores, argument classification and joins have no
live heap owner/generation. `logic.rs` relates initialized prefixes to bounded frame
regions/read epochs. `emit.rs` uses relative frame coordinates, maps IAT loads to
opaque non-observable tokens, and dispatches only four reviewed I/O effects.
Simply accepting heap imports would bypass lifetime, handle and address proof.

Complete SUB-577 in this same cohesive track by adding a reusable sum of frame,
image and heap owner-plus-offset values; nullable allocation outcome refinement;
live allocation identity through saved registers, stack locals, calls and joins;
post-free/resize invalidation; definedness for heap loads/stores and I/O borrows;
and numeric address emission without exposing the private frame backing base as
Windows ESP. Scalar pointer observations must either be proven placement-insensitive
or reject. Unknown/failed solver obligations remain rejection. Bound actual
Heap stdcall forms only after those states compose, then use the frozen programs
for genuine unchanged PE/Rust/ELF evidence. Do not replace this with a graph stencil,
application hash/name or independent algorithm answer.

ISCC/rcedit additionally require unresolved ordinary startup, TLS/SEH, modules and
many external effects. They still reject. Kernel/driver/hardware and the unverified
Wine-failure track are separate. No timeout cause is claimed fixed by this work.

## Measured instruction and utility grounding

The first Windows artifacts (af2b420 measurement) both import seven functions:
ReadFile/WriteFile/GetStdHandle and the four heap functions. The current IAT gate
rejects their 32-byte table before decoding. Independent structural decoding of
unchanged .text additionally rejects grow's SHL AL,4 at RVA10a5 and shrink's SHR
EDI,1 at RVA1077. The full shrink listing also has OR EAX,ESI for alignment checks.
Do not present those first errors as a complete list of semantic prerequisites.
Both listings contain saved registers, spilled heap handles/pointers, nullable
allocation branches, heap-indexed byte access, resize-failure cleanup, bounded fill
and copy loops, partial-register arithmetic and partial-output loops. Shrink's
reverse load uses [EDI+EAX-1] after EAX=returned pointer-counter. Copying its low byte
into AL leaves the other pointer bits present but unused by that store. This needs
bit/byte provenance, not treating an opaque pointer as a known scalar zero.

The preserved rcedit PE21efa80badc137bbcfde7d8478dd78b38b67e0081a5b9b1c46331f04d3e6a428
has calls to HeapAlloc at VA420f87, HeapFree at4224c4, GetProcessHeap at4225de and
HeapReAlloc at423323. The inspected allocation/free/resize wrappers pass flags0;
free guards null, and the resize wrapper dispatches null and zero-size cases through
other methods before the HeapReAlloc call. This is static reachability evidence,
not proof of observed execution or a license to skip the wrappers. Default-heap
initialization also reaches thread-initialization and atexit machinery, still
unresolved. ISCC's preserved import inventory has GetProcessHeap/HeapAlloc/HeapFree
and HeapDestroy; related compression modules additionally import HeapReAlloc.
Private heap lifetime, global objects, callbacks and startup remain separate gates.

Recommended continuation: one shared typed-memory/effect proof and native-emission
integration in this PR, including the observed scalar OR/shift forms with independent
flag/partial-width tests. Keep nullable outcomes and failure-preserved old pointers
on separate edges; carry allocation identity and initialized extents through spills
and joins; prove or check complete accesses and mutation effects. Do not expand
imports first or create a fixture-specific alternate execution engine. A checked
runtime access may enforce safety, but cannot by itself justify address-dependent
observable behavior or erase unknown original register bits.
