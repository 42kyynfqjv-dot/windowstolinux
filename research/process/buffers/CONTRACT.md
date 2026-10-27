# SUB-578 shared heap API buffers and scalar fields

This slice addresses shared memory requirements recorded in
[the ISCC/rcedit inventory](../DESIGN.md): managed/runtime records and borrowed
mutable resource buffers. It does not close either program's startup, TLS, SEH,
module or resource-API dependencies. The conformance programs have explicit custom
entries; neither substitutes for a third-party utility.

Source and expectations were frozen at 9808fc5 before conversion. The stream
composition applies byte XOR32 across successive 64-byte reads and partial writes;
the record composition reads two little-endian words, adds modulo 2^32 and writes
the four-byte result. Literal record expectations include carry and sign boundaries;
stream expectations are independently specified byte transformations. Original
Windows observations precede converter evaluation. Compiler output is never edited.

## Memory and API contract

Reuse the checked default heap and allocation identities from SUB-577. Each read
borrows the base of one live allocation and proves its entire requested extent.
The returned count remains in a fixed owned stack word, disjoint from the buffer.
Every read replaces that heap owner's initialized prefix with its successful count,
or zero on failure. All aliases observe this replacement; no old initialized tail
can prove a fresh read. This is deliberately conservative about physically retained
bytes and rejects programs depending on them. Other owners retain their facts.
ReadFile into interior heap addresses, heap count pointers, callbacks and concurrency
remain outside the first contract.

Heap accesses admit 8-bit bytes and 32-bit scalar fields, including unaligned full
words when all bytes lie within the allocation. Every read proves a live owner and
all bytes initialized. Stores prove known scalar bits, full bounds and no gap before
the current prefix; they may overwrite or extend it. Opaque heap/frame pointers,
handles and function tokens cannot be stored as heap scalar fields. Read values are
arbitrary bounded scalars in the proof; native emission uses the actual bytes and
x86 wrapping arithmetic. Loss of value correlation may reject valid programs but
must never authorize an unsafe access. Pointer-bearing objects require a later typed
field contract, not reinterpretation as scalars.

Failed resize retains the old owner and initialized prefix; successful resize uses
the previous reviewed transfer rules. Reads and frees cannot confer authority on a
stale owner. Heap-only input must not acquire fictitious stack-input facts. Every
successor invariant is proved before use; unknown/resource exhaustion rejects.

The native adapter invalidates read-definedness metadata, then defines only the
successful returned range; it never synthesizes a zero-filled unread tail. Byte
storage and endianness use the same checked Space as existing programs. Contract
faults remain exit125. Native synchronous file/pipe and available-resource assumptions
are inherited; EOF/failure behavior follows the actual frozen program. The stream
program treats a pipe broken-read result as error11; no pipeline-correctness claim
is made for this conformance source.

Primary requirements: Microsoft ReadFile/WriteFile, HeapAlloc/HeapReAlloc contracts
already referenced by the stream and heap designs; Intel x86 MOV/ADD/XOR operand
width and little-endian memory semantics. Independently authored MIT OR Apache-2.0
implementation and fixtures; no Wine/CRT source import.

## Acceptance gates

Twelve fixed original observations; same-PE Windows/Linux conversion and identical
Rust; exact stdout/stderr/exit comparisons. Add independent short-read, repeat-read,
EOF, read-failure and partial-write schedules, plus production negatives for stale
prefixes, incomplete words, boundary crossing, opaque fields and wrong owners.
Seven exact-emitted-adapter vectors cover byte/word aliasing, short/failing read,
resize definedness and protected count-cell boundaries; they are component evidence.
All prior compiler/utility rejection and streaming comparisons remain required.
Keep the cohesive PR draft until full CI and substantive medium review pass.

## Preserved measurement failure

The first measurement runs 40569901179 and 40569814714 stopped at frozen JSON hash
verification because Windows checkout changed line endings. No new executable
comparison was counted. Commit 9eee3fc pins JSON/Python LF checkout; frozen sources,
expected JSON contents and hashes were not changed.

## Integration evidence pending fresh CI

Local unchanged baseline PEs both translate, and twelve emitted ELF outcomes match
the saved Windows observations. These local conversions do not establish cross-host
Rust equality. Six hundred scripted emitted-program cases cover differing read/write
sizes, allocation failure, first/second-read failure, write errors and zero progress.
Five mutated PE safety checks never execute the unsafe binaries. One additional root
function checks scalar-field opaque-value rejection and mixed owner addresses; total
155 root functions, not 155 new tests. Seven adapter vectors are separately counted.

PR run40570260388 failed cl.exe's 30-second build deadline on the older grow fixture;
heap diagnostic artifact12764108599 was retained. Its later missing-artifact upload
error followed skipped steps. Push40570247048 passed all nine jobs on the same
baseline head9eee3fc. This does not explain the build timeout or validate later
production changes. No original-program timeout count is added for this build failure.
