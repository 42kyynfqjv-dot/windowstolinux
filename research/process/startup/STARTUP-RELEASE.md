# Original startup lock release

The explicit controlled native-profile entry now executes CALL0x4016b4 to the
original helper at0x401a9c, its real prolog/guard/return, and caller POP ECX.
Both empty and three-entry synthetic environment variants stop **before
CALL0x4016ba →0x401c2b**, the first conditional callback-cell accessor. Startup
state remains2 and the original normal frame remains live. Main, ordinary exit
and whole-PE/default/rcedit admission are not completed by this change.

## Independent predecessor review

Review ofd8536de found no additional production defect in the process-owned
Unobserved/Default/Guest filter slot, its ownership/lifetime and previous-result
knowledge, void-array guard selection/order, ignored EAX results, or prior effects
on later failure. The complete566-source replay manifest was independently
compared with every committed blob; generated Rust/report hashes were rechecked.
All three exact-head workflows41389107407/41389102393/41389102433 passed.

The original Windows API artifact13116334022 (run41389102433/job125096352196)
was independently read: source/frozen files match the commit, ZIP/PE/launch/stdout
hashes match, the distinct-target premise and five exchange identities passed,
and the process exited normally. This is six original API observations on
Windows Server2022 build20348, not translated-PE evidence or unhandled delivery.
Its PE is67929593300b0ee51e439deb8072d054c32d7ece1368e3b3e3ff7f204aaa2b72.
The five retained prolog/epilog comparisons remain component evidence only.

## Original semantics and supported domain

The helper's immutable29-byte body calls the existing actual0x4021bf flag helper,
TESTs EAX, and returns immediately for a zero flag. It then CMPs **one byte** at
EBP+8; nonzero returns without touching the shared word. Only flag-nonzero and
argument-byte-zero execute XOR EAX,EAX, MOV ECX,0x41cc80, memory XCHG and the real
POP/RET. No whole-argument observation or zero-extension replaces that CMP.

Reuse the existing qualified initialization exchange for the XCHG. Its domain
requires the live initialization/thread identity, canonical process-image word,
writable ordinary storage and a known scalar old value. No guest concurrency,
asynchronous interleaving or host-lock operation is admitted. XCHG returns the
old word and preserves EFLAGS, including when the old value has its sign bit set.
See Intel's [SDM, volume2 XCHG](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
for implicit locking with a memory operand and unaffected flags. The exclusive
model does not claim concurrent Windows lock equivalence.

The declared original-entry profile follows the flag-zero path. Nonzero-flag
original acquisition remains rejected earlier at the unproved TEB/CAS boundary
0x40191d; scalar instruction-component inputs do not establish a live thread's
logical lock acquisition. Unknown words, typed owner pointers and opaque lock
objects are never coerced into scalar ownership or unlocked by guessing. The
32-bit exchange cases measure owned guest-memory effects only.

Ownership/ABI/code preflight occurs before helper instructions. Branch-dependent
memory checks occur at the actual read/exchange points: the flag-zero path does
not read the argument, and either skip path does not read/write the lock word.
Thus unknown arguments, unknown words or readonly/opaque words on skipped paths
do not become implicit zeroes or unnecessary failures. Unknown low-byte decisions
still reject. Exchange failure retains the original preceding XOR/MOV/flags;
no rollback or fabricated Windows status is supplied. Pure helper execution does
not change LastError knowledge.

The caller checks the live original frame, scope0 and startup state2 before the
actual CALL, validates the returned frame, then executes the actual POP. Its
byte-initialized argument stays partially known in ECX; both consumed argument
slots are unknown rather than stale initialized data. No restoration receipt,
callback-invocation authority or exceptional-return shortcut is issued.

## Independent checks and next boundary

Thirty-two helper cases cover both skip paths, zero/nonzero/signed low bytes with
unknown upper bits, skipped unknown/typed arguments, flag/word uncertainty,
readonly and opaque words, known-scalar XCHG including all-one old data, preserved
flags/registers/LastError, expired or foreign owner/init/image, malformed ABI,
duplicate return authority, mutation, replay and failed later effects. The two
new caller mutation cases change the actual CALL/POP bytes and must reject before
caller effects. Existing protected-return, filter, initializer, resource and
canonical lifetime assertions remain intact.

Next Sol scope is0x401c2b and the actual caller's conditional callback validation,
with live image/slot reads and guarded target identity. Do not infer NULL from
initial BSS without preserving all earlier producers and reads. Unhandled filter
delivery still rejects in every process-slot state; context/disposition/default
handling, exceptional cleanup and resource-failure equivalence remain unproved.

All canonical, aggregate, Python, Clippy, formatting and152 low-stack cases remain
required, followed by a clean final commit-pinned replay. Existing historical C01,
case19 and other original-Windows timeouts remain unresolved: output/WCT do not
locate the stalled instruction/stack. Passing later CI is not a diagnosis. No
limits or comparisons were weakened. Synthetic environments only.

Local validation passed362 CRT tests (two artifact gates separately handled),
185 unwind-example tests, canonical entry with32 new helper and27 caller cases,
115 Python tests (one skip), Clippy for all targets with warnings denied and
formatting. All152 word cases passed at512KiB plus64KiB inherited padding.
Final committed-source replay and exact-head remote CI remain separate gates;
no fresh Windows release-helper or whole-PE comparison is claimed.
