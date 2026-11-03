# Original exit-table initialization and initializer return

Historical checkpoint `246087c`; the [caller continuation](STARTUP-CALLER.md)
now supersedes its next-boundary description. The completed initializer table
still does not imply complete startup or application execution.

## Connected execution

The unchanged authored PE now completes initializer callback 15 at `0x407565`
under the existing explicit native platform/ACP 65001 profiles. Its actual two
CALLs execute `0x4074fc` for separate mapped tables `0x41ce88` and `0x41ce94`, in
that order. The original 16-entry loop completes all 12 non-null callbacks, skipping its
four null initializer entries, and returns through `0x40197c` to **`0x401632`**.

The remaining startup prefix stops **before the POP ECX at `0x401632`**. Its
argument, original outer EH4 registration, scope, saved state and protected return
remain live. A new explicit rejection prevents reaching this component boundary
from returning a misleading successful whole-startup result. No outer epilog,
normal program return or unsupported instruction is substituted.

This remains original-entry **component execution**, not ordinary whole-PE
conversion. Default admission, complete startup, formatter and rcedit are still
unsupported. There are zero new Windows/ELF whole-program comparisons.

## Original helper contract

Independent expectations were recorded before implementing the emitter in
[the frozen expectations](evidence/exit-table-expectations.json). The helper:

1. Returns UINT_MAX for a null argument without dereferencing it.
2. Reads and compares the first and third 32-bit words.
3. If they differ, leaves the table untouched and returns zero. The middle word
   is not read, initialized, decoded or granted authority.
4. If equal, reads the live cookie once and executes three original stores at
   offsets 0, 4 and 8, in order, then returns zero.

The wrapper reuses those actual instructions twice and writes AL=1 only after
both calls return. It preserves the original stack convention and saved registers.
Reinitialization follows the current words and cookie. It is neither suppressed
as an invented one-shot operation nor treated as allocation/freeing.

Cookie and encoded words are scalar bits. The original stores copy the raw live cookie bits; this does not establish a
later pointer-decoding algorithm or certify arbitrary encoded function pointers,
decode them, create a capability or authorize calling/freeing one. Heap tables,
foreign stack views, unknown addresses and noncanonical module aliases are not
silently retagged. The supported non-null domain is a complete live 12-byte view
of canonical process-image storage under initialization authority. Unknown
comparison bits reject; a cookie must be a known scalar only on the write branch.
Original memory reads and conditional control remain emitted.

Both bodies and direct CALL targets are byte-bound to the unchanged PE. Ordinary
loads, stores, comparisons, branches, flags, CALL/RET and stack operations use
the existing shared decoder/emitter/runtime. There are no expected-output tables,
application-name/hash dispatches, host DLL calls or new external API success stubs.
The existing single guest thread/exclusive initialization domain is unchanged.

## Partial effects and cleanup

Every word store retains its original position. A page permission rejection on
the third store leaves the first two cookie stores visible. Failure in the second
table leaves the completed first table unchanged. The tests also preserve state
when changed code, stale storage/initialization, typed encoding or a wrong return
cleanup rejects. Unsupported failure paths do not become Windows exceptions or
successful cleanup; this is checked component rejection with prior effects kept.

The paired initializer cleanup target is **`0x401bd5`**, whose original body is
MOV AL,1; RET. That bounded no-op is bound for index 15. It does not drain callbacks,
free memory, reset the tables or undo cookie stores. Separate declared loop cases
verify its actual execution and rollback order after an independent later failure.
Those modified-table cases are labeled component inputs, not untouched-entry
acceptance. Real onexit dispatch, non-null freeing and exceptional cleanup remain
unsupported.

## Review of the shared updater

Review of `ce55f54` rechecked lock 5, actual 257/256-byte copy paths, private/global
reference ordering, normal EH4 cleanup and RET12. The copy graph's original
AND EDX,3 dominates its checked jump table; unsupported SSSE3/backward/unaligned
paths still reject. No new admission or erased memory effect was introduced.

All three exact-head `ce55f54` workflows passed: PR Rust41293857609,
push Rust41293854355 and startup41293854298. These are predecessor results;
the new-head workflow status remains separately tracked in SUB-579.

A focused additional regression uses a *distinct heap-backed old global
reference*, instead of the static old reference. Both copies and the earlier
PTD publication execute, the old global count decrements to zero, and the actual
non-null-free call rejects. The old and new allocations remain live; its global
root and held lock remain, and replay cannot repeat publication/decrements.
This closes a coverage gap without claiming that non-null free is implemented.
The inherited result corpus is now 28 cases with 28 replay rejections.

## Evidence and next scope

New native component cases comprise 21 direct-helper cases, 10 wrapper cases and
two initializer-loop success/rollback cases. They cover equal/different words,
unknown unread middle data, null input, all-one wrapping bits, partial knowledge,
typed fields/cookie, a different overlapping table view, wrong storage/owner,
stale storage, expired initialization, changed helper/wrapper bytes, read-only
writes, a later-page failure, reinitialization, no-op cleanup, ABI failure and
preservation of earlier effects. Return flags and saved state are checked.
Forged-owner tests first require ordinary transport rejection, then explicitly
corrupt test metadata to check consumer rejection too; this is not a real producer.

Five previously recorded Windows wrapper comparisons remain separate. No fresh
Windows observation or whole-program equivalence is inferred from these native
cases. The authored PE remains SHA256
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`.
Final local checks passed: 182 root, 315 CRT and 185 unwind tests; both artifact
checks/full replay; 89 startup Python (one skip), 106 tools Python and 18 corpus
Python (one skip); all-target Clippy and formatting. Fresh re-emission advanced
the source mtime and retained identical Rust SHA256
`2d23b973ef30813954596600dd50282701183c492effbbcb104d94bd549c49b4`.

[The evidence record](evidence/exit-tables.json) contains source/region hashes,
reproduction commands, failed local test logs and final verification results.

Next execute the original POP/TEST/branches and startup scope activation after
`0x401632`. The next CALL is `0x401647 -> 0x401913`. Its helper first calls
`0x4021bf`, which reads live flag `0x41d2f0`; only the nonzero branch reads
FS:[0x18]/StackBase and uses LOCK CMPXCHG at `0x401935`. Do not assume that branch
or its opposite. Execute and check the producer/flag before selecting a supported
path; reject unproved TEB/atomic ownership effects. Sol can handle the next
bounded caller/flag step. A live thread-stack/CMPXCHG ownership design, if actually
needed, is a concrete candidate for bounded Astra reasoning.

Historical original-Windows hello, corpus, output-probe, case-19 and other launch
timeout causes remain unresolved. A later passing run is not diagnosis. Local
negative-test corrections distinguished unknown-operand rejection, initialization
storage lifetime and pointer transport from later canonical-view rejection;
none relaxed runtime checks. No stack, proof or timeout limit was increased.
