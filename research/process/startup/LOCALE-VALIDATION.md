# Original locale initializer and validation boundary

This records the earlier `0f6a9c3`/`63b4afb` checkpoint. The connected API,
UTF-8 helper and cookie-return advance is documented in [LOCALE-UTF8.md](LOCALE-UTF8.md).

## Connected original instructions

Under the explicit native UTF-8 profile, entry now executes the original CALL at
`0x40b2c7`, initializer `0x40b485` frame/cookie setup, the existing selector and
its five-entry, 48-byte-stride code-page search. It reaches the actual
**IsValidCodePage CALL at `0x40b4e6`, IAT `0x4150cc`**, with argument 65001.
The API remains unbound: execution rejects before issuing a BOOL or calling an
unproved implementation. This is a forward component-execution boundary, not
whole unchanged-PE admission.

The CALL bytes are validated before creating its protected activation. The
complete 517-byte initializer is bound to executable bytes in the original mapped
image before its prolog. The CALL itself uses the shared graph emitter: its
instruction-budget check runs before creating call state. Independent exhausted
and final-available-step cases verify failure ordering and retained callee effects.
Every reachable branch remains in the normalized graph;
alternate code-page effects, unbound helper/API calls and the final return reject.
Structural decoding of the rest of the graph supplies no effect/return proof.

This additional selector invocation executes its original AND which clears
`0x41d144`. Its zero value is retained at rejection; assuming the earlier
selector's value 1 survived would erase an actual effect. The initializer's
cookie, saved registers, protected return, local selected code page and traversal
counter are on the live stack. The544-byte buffer still holds the preceding
actual copies, with unknown source bytes remaining unknown. No new locale role
or reference is published. The actual entry's initialized flag `0x41d148` remains 0;
old PTD/global references remain unchanged.

## Shared word-register semantics

The full graph exposed two existing decoder limits: MOVZX from a 16-bit register
(the actual BX source at `0x40b4e2`) and MOV into a 16-bit register from memory
(on a later, still unadmitted branch). The CRT IR now normalizes these forms
through existing scalar slice/load operations. This does not broaden the separate
production stream-graph proof policy or admit the unproved branch.

Word loads read exactly two owned, readable bytes and preserve upper destination
bits/knowledge and flags. Partial register writes discard pointer authority;
partial reads of typed words reject. MOVZX uses only known low 16 bits, clears the
upper result and preserves flags. Unknown upper source bits are not observed;
unknown low bits still reject this numeric operation. Its numeric result cannot
be used as a forged pointer. New register-source MOVZX rejects ESP destinations.
Segment/size variants outside the declared encoding subset remain rejected.

Independent native checks cover 40 word-load cases across all eight destinations
(full/partial data, stale source, forged scalar address and partial typed-word
reads),112 register-extension cases with unknown upper/low bits, and five rejected
forms. Forty-five declared locale cases include changed initializer/CALL/import,
unknown table data and an alternate table match, with strict expected outcomes.
The full replay requires the named word and REP checks before reporting them.

REP review found no demonstrated runtime defect in its dedicated effect gate,
zero-count behavior, sequential overlap, knowledge or lifetime semantics. A new
permission-boundary case copies one word, rejects a write on the next guest page
and verifies exact retained memory/ESI/EDI/ECX and flags. After an explicit checked
guest permission repair, component reentry copies only the remaining word. This
is not a Windows exception/resumption proof and changes no host permissions.

## Frozen Windows conformance before binding

[Probe](code_page_probe.c), [expectations](code-page-expectations.json) and
[source freeze](code-page-frozen.json) precede API binding. Official MSVC14.44
x86/SDK10.0.26100 CI measures 65001 valid and UINT_MAX invalid independently.
GetACP and LastError are recorded without assumed defaults. Archived source is
compiled and hashed; execution uses the existing owned-process timeout/evidence
primitive. Failed/truncated/mismatched observations cannot be counted as matches.

These observations are original API conformance only, with zero translated pairs.
They are not evidence for the target PE's ACP, Windows XP/7 behavior, or arbitrary
code-page validity. The explicit65001 profile is not default admission.
[Microsoft's IsValidCodePage contract](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-isvalidcodepage)
concerns installed Windows code pages; unsupported converter encodings must not
be converted into invented FALSE results.

## Review and next connected gate

New test failures were retained: the initial full graph rejected the word forms;
a CALL was incorrectly tested with a straight-line-only decoder; an unknown-byte
oracle incorrectly expected unobserved bits to survive a storage read; and test
state still referred to the caller's former registers/selector flag. These were
corrected to decoded CALL semantics, known-bit knowledge and the actual nested
frame/write ordering. A new mutation case initially missed the callback route;
its strict unexpected-success assertion caught that fixture mistake before push.
A final audit found the manually connected CALL omitted one instruction-budget
tick. Lowering that actual instruction through the shared emitter fixes it; the
pre-repair replay is retained separately and final-source checks are rerun.

Next bind the measured supported API result under the declared profile, execute
the original UTF-8 stores and `0x40b090` built-in classification loops, then cookie
epilogs and caller result/reference/publication/cleanup. GetCPInfo/NLS branches,
reference freeing and exceptional cleanup are still separate unproved domains.
Sol can review and continue this bounded path; escalate a concrete ambiguous
ownership or external-effect contract rather than assuming success.

Full formatter/startup/rcedit/default admission, malloc errno/new-handler,
reference freeing, exceptional EH4 cleanup, Windows capture/delivery/incoming
containment/collided unwind, native close/EOF and broader resource/encoding/XP7
equivalence remain unproved. Five recorded Windows wrapper comparisons remain
component evidence; there are zero new whole-PE Windows/ELF pairs.

See [verification and source hashes](evidence/locale-validation.json),
[retained Windows launch diagnosis](WINDOWS-LAUNCH-6DAF5AD.md),
[preceding copy contract](LOCALE-REP.md) and [dependency map](DEPENDENCIES.md).

## Windows CI test-layout repair

At 0f6a9c3, both fresh exact-image launch matrices passed 9/9 and both original
comparison gates passed. The frozen API probe observed 65001 valid, UINT_MAX
invalid, ACP 1252 and LastError 0x12345678 on Windows 2022/MSVC14.44.35207. These
are original observations, not translated pairs or evidence of the target ACP.
They do not explain the retained original-process timeouts.

Startup inventory 41279220163 nevertheless failed: the generated word-vector
Rust child's main overflowed its stack (job124767509816), skipping the three
native dependent jobs. This is a demonstrated test-harness failure, distinct
from original Windows launch hangs. Separate non-inlined case functions retain
all 40+112 assertions and increment a counter checked against 152 executions.
The Linux child now runs under a lowered 512 KiB stack; Windows default stack,
compiler limits, other tests and all timeout thresholds stay unchanged.

All 308 CRT/185 unwind checks and both artifact tests pass locally after the
repair. Emitted Rust remains c589562e7164c77a019b4f8785712249448592ba086a8490a15715dbf7897b69;
the production initializer source prefix is unchanged. The old upload omitted
the external temporary harness source/executable, so no exact old-harness Linux
recompile or PE stack-reserve measurement is claimed. Windows confirmation
requires the new fixed-head run. [Failure/fix evidence](evidence/word-register-stack.json)
and [first fresh CI observations](evidence/locale-validation-ci-0f6a9c3.json).
