# Original shared locale update and normal return

Historical checkpoint `ce55f54`; the [exit-table continuation](EXIT-TABLES.md)
now supersedes its next-boundary description. The distinct old-global heap
free-failure regression also extends the inherited result corpus from27 to28.

## Executable boundary

Under the existing explicit native platform, ACP 65001 and installed-code-page
profiles, the unchanged authored PE's entry now completes locale initializer
callback 10. CALL `0x40b362` executes the actual shared wrapper `0x40aeae`, its
EH4 registration with eight local bytes, indexed **lock 5**, copy/reference body
`0x40aefb`, unlock cleanup `0x40aeef`, normal scope exit and **RET 12**. The caller
then executes its original pointer writeback and aligned return; the callback
sets initialized byte `0x41d148` only after that return. Helper `0x407126` is
still the earlier flag XCHG, not lock acquisition.

The two actual checked-copy calls copy 257 flags bytes and 256 case bytes from
the same 544-byte heap allocation into canonical mapped global tables. Both
private and global references retain their original decrement/increment order;
no output table, reference count or success return is substituted. Normal
shared publication leaves the new count 2 and its original allocation identity
in both UCRT PTD+72 and the global reference.

The initializer then executes the already proved identical helper at table
index 14. The next rejection is **index 15, target `0x407565`**, before its effects.
That target calls `0x4074fc` twice with `0x41ce88` and `0x41ce94`; the next scope
is the original three-word exit-table initialization and failure ordering. The
helper returns UINT_MAX for a null argument; otherwise it compares first and
third words and copies the live cookie into all three only when equal, then
returns zero. This inventory is not executed support for index 15.
The existing generic rejection remains `original initializer callback effect unbound`;
the artifact test also checks the selected target, not just the error string.

This advances actual-entry component replay. It is not whole-PE conversion:
default admission, complete startup, formatter and rcedit remain unsupported.
There are **zero new whole-PE Windows/ELF pairs**. Five previously recorded
Windows wrapper component comparisons are rerun separately.

## Original copy paths and shared semantics

The complete original `0x403040` copy byte range is checked against the same
unchanged PE, including its real tail jump table. Selected graph regions use
the shared decoder, lowering and checked CPU/memory primitives. The actual
AND EDX,3 must precede table dispatch; the table words and incoming edges are
validated. Unsupported SSSE3, backward-overlap and unaligned fast-SSE paths have
explicit rejection cuts. They are not successful no-ops or a host memcpy call.
These are runtime boundaries in a component emitter, not new production
whole-program proof/admission. The default converter still rejects this program.

New reusable operations are bounded BT r/m32,imm8, forward REP MOVSB, and scalar-lane
SSE2 MOVDQA/MOVDQU/MOVQ memory transfers/register copies. BT preserves ZF,
observes CF only when the selected bit is known and clears unknown OF/SF
knowledge. Memory reads still execute; stale pointer/handle/module authority
cannot be observed as a live numeric value. MOVQ loads clear the upper 64 bits;
register MOVQ is rejected. Full vector range, permissions, alignment and typed
word protections are checked before a nonfaulting vector write. Partial-known
scalar bytes retain their masks; vector bytes never create pointer authority.
SSSE3/PALIGNR, general SIMD faults and guest concurrency are not supported.

REP commits actual units, cursor and count in order, retaining completed units
on later rejection. A zero repeat count does not dereference stale cursors.
Forward overlap follows the original instruction sequence. Pointer-typed source
words and protected control words are not interchangeable with raw vector bytes.
No scalar heap address is promoted into an allocation capability. Shared byte
table destinations additionally require the canonical process-image identity;
a stack/heap alias cannot overwrite a return slot under a global-table label.

## Ownership, cleanup and failure evidence

The real shared body revalidates the initializing process/image, normal-call
EH4 registration and held lock. Reference atomics retain the existing exclusive
single-guest-thread initialization contract. The normal epilog checks scope,
saved registers, predecessor, stack and protected return through shared proof
and emission; the outer aligned continuation remains single-use.

A failed second checked copy preserves the first completed 257-byte copy. A
first-copy failure preserves both destination tables. Cleanup-code mutation
rejects after both copies and publication, preserving the held lock and earlier
writes. Wrapper-code mutation rejects before acquiring lock 5. A destination
stack alias rejects before the copy. Replay of every result case rejects
without repeating counter or pointer changes. Unknown source bytes survive
successful publication as unknown bytes, not fabricated initialized data.

Rejected paths retain their live effects; this is **not** execution of Windows
exceptional cleanup. Invalid-argument/errno branches, non-null free, exceptional
EH4 delivery and their allocation/lock consequences remain unbound. No automatic
unlock/free/retirement is substituted for them.

## Verification and provenance

The unchanged authored PE SHA256 is
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`.
The replay independently matches wrapper, cleanup, body, checked-copy and copy
constants to executable bytes in that artifact and records their hashes.

The native copy matrix has 378 declared cases: 14 sizes × 3 source offsets × 3
destination offsets × 3 explicit dispatcher profiles. It requires 368 normal
returns and 10 explicit unsupported-path rejections. Eleven additional cases
check partial knowledge, stale source/destination/code, destination truncation
and retained progress, changed bytes, backward overlap, forged scalar address,
protected/typed words and unknown dispatch bits. These dispatcher inputs are
component declarations, not observations of host CPUID or Windows behavior.

The result corpus has 27 cases and 27 replay rejections, including six new shared
publication/failure/unknown-byte cases. Separate generated native tests exercise
24 register BT cases, four memory BT cases, six byte-repeat cases and nine vector
memory cases plus emitted register copy/strict decoding. The 45 existing callback,
49 initializer/cookie and 152 word cases remain. Named completions and successful
summaries are required; unexpected failure cannot count as success.

Final local checks passed: 182 root, 314 CRT and 185 unwind tests; both artifact
checks in the full replay; 89 startup Python (one skip), 106 tools Python and
18 corpus Python (one skip); all-target Clippy and formatting. Fresh canonical
re-emission advanced the source mtime and retained Rust SHA256
`72036164b1549c7a4fd5fc9d13594c9b46ec9243a06d48597f6ef792f9613764`.
The five recorded wrapper comparisons passed with the unchanged PE hash above.

See [the durable evidence record](evidence/locale-shared.json),
[dependency map](DEPENDENCIES.md) and
[reproduction harness](check_normal_wrapper.py). Predecessor `dfb3d77` has three
successful exact-head workflows: 41288514033, 41288510348 and 41288510354. New-head
CI conclusions are tracked in SUB-579; a running workflow is not a pass.

The local generated primitive test initially exhausted its unchanged 512 KiB
stack; splitting independent cases into non-inlined functions resolved that
failure without larger limits or removing cases. A new repeated-callback oracle
also incorrectly assumed known upper EAX bits; the actual fast path writes AL
only. The corrected assertion preserves unknown upper bits. Failed local logs
are retained and hashed. Historical original-Windows hello, corpus, output-probe,
case19 and other launch timeout causes remain unresolved despite later passes.
No timeout threshold, proof limit or stack limit was increased.
