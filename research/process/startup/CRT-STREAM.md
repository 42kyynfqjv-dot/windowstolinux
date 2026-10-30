# Original CRT stream lifecycle gate

This is one cohesive continuation of SUB-579: prove the original stream state,
formatter output path and teardown together. The existing
[Main completion](MAIN-COMPLETION.md) component explicitly supplies a stdio
effect. It does not yet establish these linked CRT effects. The differences
below are outstanding equivalence obligations, not a claim that the explicitly
conditional component violates its own contract.

[stdio-frozen.json](stdio-frozen.json) freezes independent expectations before
the new stream implementation. Expected values come from the original machine
instructions, authored byte vectors and public API contracts. They are not
computed by the production converter, emitted Rust or its fixture generator.
The manifest is not a completed test report.

## Implemented component boundary

`examples/crt_stream.rs` now compiles the original narrow text writer, descriptor
selection, console exclusion and errno mapping into native Rust. Each admitted
instruction graph is checked before emission. The writer and flush certificates
use bounded, parameterized instruction protocols; they are not a general proof
for arbitrary CRT graphs. Structural inventory alone grants no emission authority.
Generated code has checked owned memory and compiled control flow, with no decoder,
solver, Wine or AI dependency at runtime.

The selector calls the original writer and the separately proved error mapper.
The caller supplies a live, initialized narrow descriptor, input, context, committed
fault-free stack and cookie. These are explicit component preconditions. The
descriptor-lock/EH4 wrapper at `40df1c` is not aliased to the selector at `40e02d`.
Pending context errno fields do not establish a later commit into Windows PTD.

The original flush and stream initialization/teardown bodies also compile through
the shared emitter in focused tests. Their unresolved callees have declared test
contracts. In particular, failed lock initialization does not create a valid lock,
and shutdown requires its own phase authority after Main. Those tests do not
establish the original startup or normal-exit call chain.

Independent review found and fixed pointer TEST-versus-CMP confusion, reading
call-clobbered unknown values as available inputs, discarded protected stack
words, stale descriptor assumptions at teardown, and freed-pointer transport.
Further independent review reproduced an alias between an original executable
region and the component's writable stack. Complete code, data and IAT extents
now exclude each other and all constructed component storage before emission.
The last lifetime distinction matters: original code can copy or clear a retired pointer
word, while dereference, arithmetic and free still require its live generation.
Address reuse cannot revive an old pointer. Each finding has a focused regression.
The stack-probe regression also covers saving unknown register bits without
mistaking their canonical stored representation for a different protected value.

### Recorded Windows observation and native checks

Observer checkpoint `1aa2a51df0f66ef7d9620b13787c3c05a394c507` passed dedicated
[CI 40636074964](https://github.com/42kyynfqjv-dot/windowstolinux/actions/runs/40636074964)
and both full regression runs. Its unchanged original PE SHA-256 is
`45b0a49607edc860fb705bbfb5eff96ccaf91805a9058b3f9efbd2261da3c0b7`.
It retains the frozen source identity and relevant instruction-region hashes;
this freshly linked artifact is distinct from the earlier PE below.

All five original observer cases and the forced cleanup-failure control passed
on Windows Server 2022 build 20348. In these runs, printf returned 275 and Main
returned 0 **before** the WriteFile call. The write occurred during shutdown.

| Original API outcome | Writer triple | Logical return | Flush return |
| --- | --- | --- | --- |
| Real full write | `[0, 276, 1]` | 275 | 0 |
| Scripted success, count 7 | `[0, 7, 1]` | 6 | `0xffffffff` |
| Scripted success, count 1 | `[0, 1, 1]` | 0 | `0xffffffff` |
| Scripted success, count 0 | `[0, 0, 1]` | `0xffffffff` | `0xffffffff` |
| Real invalid-handle failure | `[6, 0, 1]` | `0xffffffff` | `0xffffffff` |

The three scripted successes skip the OS call and write no physical bytes.
The invalid-handle case executes the real OS call with a substituted argument.
Dynamic errno/PTD fields were not observed. Native context checks use the separate
frozen predictions, not an invented Windows observation.

`check_stdio.py` checks original PE/object/source identities and raw observer
receipts before compiling. It runs 21 unique scenarios: 16 frozen byte/API vectors
and five projections of the observed original payload. Both direct text and
composed selector entries run for each scenario (42 component invocations per
host). It checks exact request bytes, call counts, triples, logical returns and
pending context fields, then compares deterministic generated Rust and results
between Windows and Linux. The five projections remain five original observations,
not ten. None is a whole-PE translation pair. Three supplemental native-only
empty, maximum-LF-expansion and oversized-input scenarios add six entry
invocations. The oversized case rejects both entries before any backend call.
They are counted separately and add no original Windows observations.

Local review passes 56 CRT example test functions (46 new and 10 inherited graph
tests), 175 unchanged root tests and all existing example targets. Python startup
discovery runs 43 tests, with the artifact-dependent frame gate deliberately
skipped there and exercised separately by CI. Formatting and Clippy with warnings
denied pass. Fresh cross-host results for this implementation must come from its
own workflow head; the observer checkpoint above does not certify later code.

Reproduce with the `startup-unwind-slice` and `startup-stdio-observation` artifacts
from the same dedicated workflow run:

```sh
cargo test --locked --example crt_stream
python3 -m unittest discover -s research/process/startup -v
python3 research/process/startup/check_stdio.py ORIGINAL OBSERVED OUTPUT \
  --compare ORIGINAL/stdio-native-windows/report.json
```

The remaining connected gate is original formatter/context execution, the
descriptor lock/exception wrapper and actual startup-to-normal-exit callback and
flush/close composition. Main's earlier conditional stdio boundary is not replaced
until those effects are proved. Full startup, rcedit and general CRT admission stay
rejected. Historical original-Windows timeout causes remain unresolved; a later
passing run does not establish their cause.

## Exact retained evidence

The retained directory is `/tmp/w2l-reported-final-7ee6`. Its original PE SHA-256
is `b5b35164c4af09d010b555c6439a97040568cc221b267ca993b9275f6377ddd9`.
The source SHA-256 is
`143932ec0de25e0e3269c4d7774d78f411efae331e8aa52dd3c97cae05ecaeb1`;
the compiler identifies itself as MSVC 19.44.35229 for x86. The object and eleven
bounded instruction-region hashes are in the manifest. Earlier retained PE
hashes remain separate artifacts even when relevant instruction bytes match.
No source or original PE edits are part of this gate.

Addresses below describe this artifact at its preferred base. Production must
derive bindings from original instructions, checked relocations and owned image
regions; neither addresses nor function names authorize an application-specific
replacement.

| Original region or edge | Effects that require closure |
| --- | --- |
| `401520..40154c` | Original printf wrapper routes format, scalar argument cursor, stdout and both option words. |
| `4045d8..4045e8` | FILE address calculation: base `41c080`, stride 56, stdout index 1. The address does not establish lifetime or initialization. |
| `40643e..4064e2` | Formatter entry, FILE/format checks, local context and error cleanup. |
| `4051e0..40523d`, `405240..40527c` | Locale selection and pending errno/doserrno updates committed to the thread state. |
| `40465c..4046b7` | Stream lock, original exception-protected formatting call, unlock cleanup, FS predecessor restoration. |
| `4052ba..405356` | Temporary buffering, parser execution, formatting storage cleanup and buffer completion. |
| `405584..405809`, table at `40580c` | Format-state traversal, indirect dispatch and supported conversion paths. The jump table is data, not executable linear disassembly. |
| `409e12..409ebd`, `409ebd..409efb` | Conditional temporary buffering, allocation fallback and conditional flush/reset. |
| `409da7..409dd4`, `4100fa -> 40fea3` | Buffered character insertion and capacity/stream-mode slow path. |
| `40ff99..41006b`, `411de9..411e45` | Capacity flush, retained next character, ordinary allocation and fallback. |
| `408420..408489 -> 40df1c -> 40e02d` | Flush state reset, descriptor validation/locking, low-level mode and result handling. |
| `40dc26..40dd01`, result at `40e1c8..40e249` | Narrow text conversion, WriteFile effects, short-write and error accounting. |
| `404510..4045d8`, `408697` | FILE table/locks and low-I/O initialization, including inherited handles and standard-handle queries. |
| `4045e8..404634` | Flush-all, additional-stream close traversal, standard buffer release, lock destruction and table release. |

## Reusable admitted domain

The proof must bind a process, CRT runtime instance, thread, FILE, descriptor,
buffer and synchronization object with independent identities and lifetimes.
An initialized pointer field is not interchangeable with an integer containing
the same address. All reads and writes require complete initialized ranges,
permissions and exclusions for code, return slots, exception metadata and other
owners. Retired buffers and streams cannot regain authority through aliases.

The first coherent domain is narrow text output through a live synchronous
descriptor, with known C-locale state, complete option words and a bounded
integer-format grammar. Scalar values remain variable, including signed limits;
the frozen report string and its successful result are not an instruction
recognizer. Unsupported format directives and argument types reject before
emission unless their actual reachable effects are proved.

Console/Unicode conversion, append seeks, concurrent mutation, locale changes,
invalid-parameter callbacks and arbitrary additional streams remain separate
requirements. Their branches may be excluded only by checked state and
reachability facts. A successful sample, a null sampled callback or a symbol
name does not establish that exclusion. The original invalid-parameter path at
`407ad2` can call a thread/global callback or terminate; it cannot silently become
an ordinary negative return.

The formatter's context constructor can obtain locale globals directly or defer
to thread state. Its destructor can commit errno/doserrno and release a temporary
locale-state flag. Error paths therefore require valid initialized PTD ownership
and the relevant API contracts. They cannot fabricate a PTD or set unknown error
fields to zero. Successful writes do not make arbitrary preexisting errno known.

## Original text-write and flush semantics

The narrow writer constructs a physical chunk before calling WriteFile. Each
LF becomes CR LF; other bytes, including NUL, CR, Ctrl-Z and high bytes, retain
their byte values in the admitted non-console text path. The chunk threshold is
5119 physical bytes, checked **after a complete source-byte expansion**. Thus
5118 ordinary bytes followed by LF form one 5120-byte request; 5119 ordinary
bytes followed by LF form requests of 5119 and 2 bytes.

The synchronous callback returns success plus a count in `[0, requested]`, or
failure plus an error. An impossible success count rejects the effect contract.
The original helper reads GetLastError only on failure and does not consume the
failure count as committed bytes. Output-count storage, output buffers and the
descriptor are distinct owned objects. Asynchronous completion is outside this
contract.

The helper stops after any short successful write, including zero, and after
failure. It does not retry the unwritten suffix. Only a full successful chunk
permits constructing the next chunk. Its returned triple is:

1. the failure code, initially zero;
2. cumulative physical bytes reported by successful calls;
3. cumulative inserted CR bytes in all chunks already constructed.

If physical progress is nonzero, `40e23d` computes the logical result by wrapping
32-bit subtraction of the third field from the second. This is not a count of
fully written source characters. For input `LF LF`, a synthetic successful count
of 1 produces `0xffffffff` while leaving pending errno/doserrno unchanged. A
later failed chunk can also have inserted-CR accounting without any physical
progress from that chunk. The manifest freezes these otherwise easy-to-miss
cases. They are predictions from original instructions, not ordinary-file
short-write observations.

With no physical progress, the original result path applies error mapping. In
the bounded cases, successful zero progress maps to errno 28/doserrno 0;
ERROR_ACCESS_DENIED maps here to errno 9/doserrno 5; error 6 maps through the
original table to errno 9/doserrno 6. Other error mappings require their own
bound evidence. Prior positive progress takes the positive-progress branch;
the pending error-state writes must not be inferred from a later failure alone.

Flush resets FILE pointer to base and count to zero **before** the write. A
returned logical count different from the queued input length sets the FILE
error flag and returns `0xffffffff`; bytes already written remain observable.
Success does not clear an older stream-error flag. The old queue is not retained
for a generic retry after the reset.

The capacity path is different. It first sets pointer to `base+1` and count to
`capacity-1`, writes the previous buffer, and then stores the new character at
base even when the previous write was short or failed. The caller sets the
stream-error flag on mismatch. A transactional queue that rolls everything back
would erase original effects.

## Allocation, locks and lifetime

Ordinary buffer allocation requests 4096 bytes. On success, FILE gains the
owned-buffer flag. On failure, the original code uses the embedded two-byte
FILE cell and the unbuffered flag `0x400`; its slow path then writes one character
directly. It does **not** behave as an ordinary two-byte queued buffer.

Temporary stdout buffering has a different path: it sets temporary flags
`0x282` and may also fall back to the embedded two-byte cell, but the resulting
flags retain buffered operation. Allocation failure's errno effects remain
those of the actual allocator and must not be cleared by a convenient fallback.
Temporary completion conditionally flushes and clears its buffer pointers even
if the flush failed; heap-cache lifetime must follow the original owner.

The original stream wrapper enters the FILE lock at `404640` and leaves it at
`404654`. Both normal return and admitted exceptional cleanup must preserve that
ordering. Merely swallowing an exception or dropping a host mutex is not proof
of the original guest cleanup and FS effects. Lock/descriptor teardown cannot
occur while a callback or buffer borrow remains live.

The standard-stream teardown starts by flushing. The additional-stream traversal
at `40819d` starts at index 3 and reaches close helper `40d627` for active extra
streams. Their close contracts cannot be silently omitted. Under a proved
no-additional-stream domain, the loop releases buffer 0 then destroys lock 0,
then does the same for streams 1 and 2. It must not regroup all buffer releases
ahead of all lock deletions. The stream table is then freed and cleared. `4045e8` itself does not
call CloseHandle on standard handles; this is not a claim that handles remain
open after process termination.

## Main return is not normal process exit

Original entry `4017a4` reaches CRT startup and calls Main at `401717`. The C
initializer table includes stream initialization `404510`; other initializers,
security, thread state, arguments/environment and callbacks still need their
existing closure gates. Selecting the formatter does not authorize a guessed
Main entry.

Main's printf result is ignored. Its independently computed EAX value then
passes through the proved protected return. A later flush failure must not
rewrite that Main result or be confused with a failure to return from Main.
The original normal-exit path reaches `407040 -> 406e69`, callback traversal and
the pre-termination table containing `4045e8`. Callback ordering and effects
remain observable. The new milestone must connect stream initialization and
shutdown to these actual call sites rather than inserting an arbitrary flush
before Main returns.

## Frozen checks and evidence accounting

The manifest contains 16 writer cases, 5 flush cases, 6 buffer cases, 4 lifecycle
gates and 10 rejection gates. Those are conformance rows, not test-function or
Windows-execution counts. They cover full/short/zero/error writes, CRLF splitting,
wraparound, multiple chunks, reset-before-write, effects retained after failure,
allocation fallback and resource ordering.

Five original-artifact Windows observer cases are frozen separately:

- An unaltered regular-file WriteFile observation.
- Three explicitly scripted API results: TRUE with count 7, 1 or 0 for the
  unchanged 276-byte request. The observer skips that imported call, supplies its
  documented call-state effects and executes subsequent original instructions.
  The physical file remains empty; these are not real OS short writes.
- A real WriteFile failure using an invalid handle argument on the observer's
  disposable process. The OS call executes. Error 6 is the pinned-host prediction
  to verify, not a universal error-selection promise.

The observer must preserve PE hashes, restore any debug breakpoint bytes, own
and clean up its child, and record original call/return addresses, counts, FILE
fields, lock order, printf result, Main return and flush result. Failure to reach
an expected breakpoint is a failed observation. No hidden retry or changed
timeout threshold is part of this gate. Ordinary baseline output remains
separate from these instrumented runs.

Implementation acceptance requires instruction-derived bindings and effect
order, independent native cases and proof mutations, plus those original Windows
observations. Unsupported locale/callback/mode/lifetime paths must reject before
emission. Passing a native component is not a whole-PE translation claim. Full
startup, arbitrary CRT applications, ISCC/rcedit and XP/7 remain outside the
demonstrated domain until their separate composition gates close.

## Primary contracts

- [WriteFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile): synchronous result/count, zeroing the count before work, documented nonblocking-pipe short writes and failure retrieval.
- [GetLastError](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror): thread-specific error and the need to read it at the documented failure boundary.
- [printf](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/printf-printf-l-wprintf-wprintf-l?view=msvc-170) and [format syntax](https://learn.microsoft.com/en-us/cpp/c-runtime-library/format-specification-syntax-printf-and-wprintf-functions?view=msvc-170): conversion and public return semantics; not a specification of private FILE layout.
- [_write](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/write?view=msvc-170), [_setmode](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/setmode?view=msvc-170), [fflush](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/fflush?view=msvc-170): byte modes, logical counts and buffer effects.
- [EnterCriticalSection](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-entercriticalsection), [LeaveCriticalSection](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-leavecriticalsection): synchronization ownership; initialization and exceptional paths require their actual separate contracts.
- [exit, _Exit, _exit](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/exit-exit-exit?view=msvc-170): callback and stream-flush distinctions.

No proprietary runtime source is imported or ported. Private layout and control
facts here are evidence from the user's authored, unchanged compiled artifact;
the reusable native effects are independently implemented.
