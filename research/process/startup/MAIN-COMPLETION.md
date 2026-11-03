# Conditional original Main completion

This component extends the [owned software exception event](RAISED-EVENT.md)
through the original authored program's reporting and normal return
instructions. It connects the live selected activation to a checked return
receipt. It does **not** admit the whole PE, replace ordinary CRT startup, or
establish the effects of the statically linked formatter and CRT termination.

The experimental entry is `prove_reported`. Its inputs include original code,
bound addresses, initialized owned state and an explicitly declared stdio effect.
The separate artifact extractor checks original COFF relocation provenance.
A supplied callback, matching output, function name or binary hash is not proof
that the original formatter implements that effect. The ordinary converter's
unsupported startup boundary remains in force.

## Original instruction and data provenance

The source and compiler configuration remain frozen in
[unwind-frozen.json](unwind-frozen.json). The source is
[unwind_probe.c](unwind_probe.c), compiled with MSVC x86 `/O2 /GS` and ordinary
Windows CRT entry. No original executable bytes are edited for this component.
[reported_binding.py](reported_binding.py) binds the Main call, wrapper and
address-bearing leaves through the original COFF relocations and matching PE
bytes. That evidence extraction is separate from production instruction proof.

These preferred-base addresses identify the retained evidence. They are not
application-specific production dispatch keys:

| Original region | Evidence and effect |
| --- | --- |
| Main `0x4013b7` through `RET` at `0x40151b` | Read computed state, form variadic arguments, call the wrapper, compute Main's result, restore the predecessor and saved registers, check the cookie, return. |
| Wrapper `0x401520..0x40154c` | Preserve ESI, acquire stdout for index 1, derive the original variadic-list pointer, obtain the options pointer and route six argument words to the bound formatter. |
| I/O accessor `0x4045d8..0x4045e8` | Original arithmetic derives `0x41c080 + index * 0x38`; index 1 gives stdout object address `0x41c0b8`. |
| Options accessor `0x401270..0x401276` | Original instructions return options-cell address `0x41d2e8`. |
| Formatter entry `0x40643e` | Bound static function target. Its body and dependencies are **not** proved by the wrapper proof. |
| Format at `0x4151a0` | 277 bytes before the terminator, **278 bytes including NUL**. |

The full format bytes have SHA-256
`8a0c4771ba4049fa18410ed93f0919292338f405dcde2ba0db7e5e5451f0e2b1`.
The retained PE with SHA-256
`55a2435e8800b54f81c20b55373b56206c24bdeeeadc9580bb39b80bf5e04ce5`
and the later retained PE
`c6c0f5d9d81de6f9640564a2b6b503b4c28ead099d27c3ba299ea42aa05e7782`
have identical referenced wrapper, accessor and format bytes. Different complete
PE hashes remain distinct artifacts; a fresh cross-host comparison must carry
its own exact PE and generated-source hashes.

The compiler in [main_completion.rs](../../../src/main_completion.rs) follows
the decoded operands and forward branches. It derives the argument order,
complete stack cleanup and original comparison result. Typed frame loads
distinguish scalar, stack, module and continuation words from protected or
uninitialized storage. Module-relative observations require the same owned
module base; arbitrary integers do not become image-pointer authority.

The wrapper compiler in [stdio_effect.rs](../../../src/stdio_effect.rs) verifies
the two leaf accessors, actual call order and the formatter's six stack words:
options low, options high, stdout pointer, format pointer, null locale and
original variadic-list pointer. It requires balanced wrapper stack state and
restored nonvolatile registers. Code regions, stdout storage and options storage
must not alias. Its reported temporary depth covers the decoded wrapper and
accessors; the unproved formatter's guest stack requirements remain external.

## Variadic values and unknown call results

The immutable format consumes 17 initialized 32-bit words, plus the format
pointer itself. Main's original `ADD ESP,0x48` therefore consumes 18 words.
Windows `int` and `long` are both 32 bits in this x86 ABI:

| Format | Fields | Interpretation |
| --- | --- | --- |
| 13 `%lu` conversions | Table RVA, three cleanup RVAs, restore RVA, restore-target RVA, trace, inner, outer, selected, handled, abandoned, restore EAX | Unsigned 32-bit decimal. |
| Two `%ld` conversions | Inner and outer custom cursors | Signed two's-complement 32-bit decimal. |
| Two `%d` conversions | Restored-stack and restored-frame equality | Signed 32-bit decimal; the original instructions compute the values. |

Formatting uses runtime arguments produced by the original Main instructions.
It does not substitute the expected observation record or a precomputed line.
The bounded formatter also admits `%u` and `%%`; widths, precision, strings,
pointers, floating point, `%n`, other length modifiers and non-ASCII format
bytes reject. The complete terminator and argument ranges must be initialized.

The original `printf` call is at `0x401466`. Main ignores its returned EAX and
then performs its own comparisons. The proof invalidates caller-clobbered EAX,
ECX, EDX and flags at that call. Unsupported reads of those unknown values do not
inherit previous values. Later original instructions compute Main's own scalar
return value; a printing error cannot replace it with a new exit code.

`PrintResult::Count` represents the logical formatted-character count.
`PrintResult::Negative` represents the public error class without inventing an
exact negative integer. Its scalar projection is unknown. A callback `Err`
means that the declared component contract could not be satisfied; it is not a
substitute for an admitted CRT I/O error. Ordinary I/O failure returns the error
class successfully to the original Main continuation.

## Owned normal return is separate from unwind

[main_return.rs](../../../src/main_return.rs) consumes the already completed
event and selected activation. The original exception transfer and restoration
must have finished first. A normal-return session then requires the original
EH4 level to be inactive and binds the exact frame, owner, event generation,
registry identity, saved values, cookie and caller stack position.

The original epilog drives the effects in order:

1. Restore the typed FS predecessor. Its identity may be borrowed; it is not
   converted to a numeric zero or dereferenced as an owned registration.
2. Consume the original guard-discard and saved-register slots in their decoded
   order. Unknown saved values remain unknown.
3. Validate the original cookie operation and bound security-check target.
4. Restore the caller's frame register and consume the protected return slot.
5. Retire the selected frame only at that validated normal return and issue a
   single-use, owner-bound receipt.

An unwind cleanup receipt cannot authorize normal return. Reordered pops,
foreign or replayed identities, changed saved words, premature retirement or a
missing guard check block the session. A failed session does not hide effects
already performed, such as a predecessor restoration or prior output. The
caller continuation remains opaque. Returning from Main is not itself proof of
CRT exit callbacks, buffer flushing or process termination.

## Explicit stdio state and buffering policy

`OwnedStdio` is a declared effect at a CRT boundary. The current domain requires
an initialized owned stdout object, narrow C-locale formatting, text mode,
absence of intervening or concurrent stream/errno observations, and a complete
known options value `[0x24, 0]`. These are supplied domain conditions, not
results of proving ordinary startup.

The observed startup helper ORs the low options word with `0x24` and preserves
the high word. That operation alone does not prove that the high word is zero
or establish all FILE, locale, locking and runtime initialization effects.
Likewise, an accessor returning the expected address does not establish the
pointed-to object's lifetime or the linked formatter's behavior.

Buffering is explicit:

| Policy | Component behavior | Required interpretation |
| --- | --- | --- |
| `Deferred` | Formatting validates input and appends text-converted bytes to a bounded owned queue. It returns a character count without calling the sink. A separate `flush` performs writes. | Models a declared queue/flush boundary. It is not an inference about the original FILE's buffer capacity, automatic flush schedule or default redirected-stdout behavior. |
| `ImmediateProjection` | The same formatting is followed by a component flush before the call returns. | Requires a separate unbuffered/output-projection premise. It must not silently stand in for ordinary redirected CRT stdout. |

Literal LF expands to CRLF under this text-mode domain; other permitted literal
bytes retain their order. The `printf` count precedes this expansion. For the
retained successful observation the count is 275 logical characters and the
physical output is 276 bytes. A complete output observed after Windows process
exit does not reveal when the CRT issued its writes.

Positive partial writes advance the sink prefix. A write-zero or sink error
marks the stream error and leaves exact errno unknown. The prefix already
written remains observable. On a failed component flush the remaining queue is
discarded; recovery, retry and `clearerr` behavior are outside this bounded
domain. Deferred `printf` may already have returned a successful count before
that flush fails. Neither failure rewrites Main's independently computed result.

Format/owner/resource violations are rejected before output, where possible;
they are different from supported I/O failures. Full format validation precedes
queue mutation. Queue overflow rejects without discarding an earlier queued
message. A sink claiming more bytes than requested violates the effect contract
and is not treated as an ordinary CRT failure.

Microsoft documents normal `exit` as processing registered callbacks and then
flushing stream buffers; `_exit` and `_Exit` do not perform those operations.
This component implements neither termination path. A separate explicit flush
can support a conditional final-byte comparison, but cannot establish the
ordering or effects of the original CRT's callbacks and shutdown.

## Evidence and completion gates

At this documentation checkpoint, the focused wrapper/format/native-stdio
checks have run locally, including actual original wrapper bytes and the
complete original format. Independent native checks exercise signed limits,
partial writes, deferred failure, CR/LF boundaries, owner/alias rejection and
queue capacity. These are component checks; they are not additional Windows
observations or whole-PE translation pairs.

The integrated reported mode passed locally against retained original PE
`c6c0f5d9d81de6f9640564a2b6b503b4c28ead099d27c3ba299ea42aa05e7782`.
Generated Rust SHA-256 is
`7fcb60b11234c59935070b2ff215f6f59603d614b7ba0e148e36e7afa8c6870c`.
The checker executed 22 named component cases, 11 runtime rejections and 13
compiler mutations. One successful explicit flush produced the same 276 bytes
as the retained original Windows baseline. Main returned zero independently of
the harness exit status. The other scalar, buffering and failure scenarios are
independent native checks, not 22 original Windows observations.

Local formatting, all-target Clippy, 175 root tests and 153 example test
functions pass. The example count is 136 inherited plus 17 new functions, not
an aggregate of duplicated imported suites. Seven evidence/oracle checks pass.
Review retained fixes for stale temporary ESP, partial-word initialization,
filter aliases with initialized storage, and compile/runtime object alignment.

Fresh exact-head cross-host CI remains **pending at this checkpoint**. The
published report must record:

- exact source/configuration, original PE, extracted-region and generated-Rust
  hashes;
- which original Main instructions and return effects executed;
- independently expected binary output and Main return values;
- separate immediate-output and deferred-flush failure cases, without treating
  scripted sink outcomes as fresh operating-system observations;
- rejection of unknown call results, protected/foreign state, wrong argument
  order, stale return receipts and unsupported format/effect assumptions;
- the explicit difference between a conditional component comparison and
  successful conversion from the original PE entry through process exit.

Pre-Main CRT initialization, the static formatter and its locale/locking/error
dependencies, original process interception assumptions, exit callbacks and
normal-exit flushing still require closure before a whole-entry claim. Existing
ISCC, rcedit, ordinary CRT and XP/7 compatibility limits remain unchanged.
Historical Windows timeout causes also remain unresolved; this component does
not alter thresholds, add hidden retries or explain those failures.

## Primary contracts

- [printf and related functions](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/printf-printf-l-wprintf-wprintf-l?view=msvc-170): character count, negative error result and stream constraints.
- [printf format specification](https://learn.microsoft.com/en-us/cpp/c-runtime-library/format-specification-syntax-printf-and-wprintf-functions?view=msvc-170): conversion types and argument interpretation.
- [Data type ranges](https://learn.microsoft.com/en-us/cpp/cpp/data-type-ranges?view=msvc-170): Windows integer widths.
- [_setmode](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/setmode?view=msvc-170): text/binary and Unicode translation modes.
- [setvbuf](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/setvbuf?view=msvc-170): explicit stream buffering modes and size.
- [fflush](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/fflush?view=msvc-170): flush results, discarded buffers and possible data loss on failure.
- [ferror](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/ferror?view=msvc-170): stream-error state.
- [exit, _Exit and _exit](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/exit-exit-exit?view=msvc-170): callback and flush distinctions.
- [Internal CRT globals and functions](https://learn.microsoft.com/en-us/cpp/c-runtime-library/internal-crt-globals-and-functions?view=msvc-170): internal interfaces are implementation details; their names alone do not grant a stable replacement contract.

The code is independently implemented Rust. No proprietary CRT implementation
or Wine source is imported.
