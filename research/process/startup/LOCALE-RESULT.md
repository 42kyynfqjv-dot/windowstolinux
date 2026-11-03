# Original locale result, reference publication and cleanup boundary

Historical checkpoint `dfb3d77`; the [shared-update continuation](LOCALE-SHARED.md)
now supersedes the next-boundary description below.

## Connected execution

The explicit native-profile entry now executes original caller `0x40b2cc` after
the original UTF-8 initializer returns. It pops the real arguments, follows the
result branch, decrements the old reference using original LOCK XADD/DEC, writes
the new allocation's count 1 and publishes that same pointer into UCRT PTD+72.
It then prepares the real local arguments and stops at **CALL `0x40b362` to
`0x40aeae`**, whose shared-publication EH4 effects remain unbound. The earlier
publication and decrement survive rejection. Global locale roots and startup's
initialized flag remain unchanged; the flag is still zero.

A separately declared per-thread-mask component skips that shared-update branch,
executes the original `free(NULL)` instructions and aligned epilog, and returns
normally. Its connected callback sets the initialized flag only after that real
return. The mask is an explicit component input; the original entry's data is
not changed to take this branch. This is not whole-PE conversion or full rcedit
support, and it introduces zero new whole-PE Windows/ELF pairs.

## Review correction: the helper is a flag exchange

Review of `c0d42a7` found no demonstrated defect in its UTF-8 classification,
unknown-byte handling or cookie returns. All three exact-head workflows passed:
Rust PR `41285093520`, Rust push `41285089827`, startup `41285089873`.

The prior next-step description incorrectly called `0x407126` a lock helper.
Its actual bytes execute XOR EAX,EAX; MOV ECX,`0x41ce7c`; INC EAX;
**XCHG [ECX],EAX; RET**. The new implementation executes this sequence; it
does not fabricate a lock acquisition or indexed-lock lease. Its flag effect
remains visible if a later reference operation rejects.

## Bounded shared instruction contracts

The default decoder and loader-cache XCHG behavior are unchanged. A consumer
explicitly qualifies a decoded memory XCHG or LOCK XADD as an initializing
scalar atomic and must supply its effect gate. Missing gates, other encodings,
partial widths, register destinations and ESP/EBP sources reject. No memory read
is erased by qualification.

The shared effect requires live process-image and initialization authority,
aligned writable storage, known scalar operands and canonical mapping or exact
whole unowned heap-buffer identity. A numeric heap address cannot become a
pointer. Foreign, stale, interior and partial allocation views reject. It uses
original wrapping arithmetic; XADD returns the old word and sets sum flags,
while XCHG preserves flags. Checks precede the write and no host callback can
interleave with it. This is the existing **single guest thread, serialized
initialization domain**. It is not a proof of concurrent guest execution or a
replacement for the existing indexed-lock contract.

The caller validates the live UCRT/FLS view before its PTD dereferences and
publication. The new buffer keeps its allocation identity and byte knowledge;
only original stores initialize its counter. New/old self-aliasing rejects at
the reference effect point. There is no retagging, shadow reference count,
second buffer or synthesized output table.

The aligned activation claims the result continuation once, bound to its real
process/thread/fiber, protected return identity and checked numeric mirror.
Failures consume this claim too. A replay cannot decrement, publish or release
again. Ordinary original returns still require exact saved-register/stack and
protected-token validation; a numeric copy never authorizes RET.

## Cleanup and failure ordering

The complete original `0x407d50` free body is byte-bound. Its null branch runs
the actual prolog, comparison, branch and RET without calling HeapFree. Every
non-null API/error path remains explicit rejection at its original call. No
success/failure outcome, lifetime change or errno is invented. If an old count
reaches zero, the preceding decrement and argument pushes survive rejection;
the new pointer is not published, and neither allocation is reported freed.

The initializer's -1 result branch rejects its unbound errno acquisition. Cookie
failure, shared-publication EH4 handling, exceptional cleanup, malloc errno/new
handler and non-null free remain unsupported. This does not close the broader
delivery, resource, encoding, native close/EOF or default-ACP equivalence gaps.

## Verification scope

Twenty-one independent component cases run the actual initializer for each fresh
buffer, then declare post-initializer frame inputs. They check normal return,
shared-update rejection after publication, heap and module old references,
zero/max wrapping counts, non-null free rejection, stale/new/old identities,
unknown and typed counters, wrong PTD, unknown heap provenance, return-mirror
corruption, changed caller/flag/free bytes and initialization/provider lifetime.
Every case attempts replay and requires unchanged post-result memory.
Twenty-six separate scalar-atomic cases check values, flags, failure classes,
permissions, identity, unknown bytes and unchanged prior state on rejection.
The preceding 49 initializer/cookie cases and all 152 word cases remain.

The actual entry/callback cases separately test the original prolog and complete
connected path. The manually declared post-initializer test frame is not evidence
for Windows capture or whole-program startup. Five recorded Windows wrapper
component comparisons remain separate from these native cases; no new Windows
whole-PE pairs are claimed. Reproduction, hashes, failures and final-source checks
are in [the evidence record](evidence/locale-result.json).

Local verification caught a production build depending on a test-only constant,
then three manually constructed negative-test frames missing the new claim field.
The free bytes now live in a production constant, agree with the existing free
component and are independently matched against the unchanged PE. Negative frames
were updated without dropping cases. Failed logs remain retained; full final
replay is required after these corrections.

The corrected final source passed 182 root tests, 311 CRT tests, 185 unwind tests,
both artifact checks, the complete replay and all-target Clippy/formatting.
Python checks passed 89 startup tests (one skip), 106 tools tests and 18 corpus
tests (one skip). The five recorded Windows wrapper comparisons passed, and a
fresh artifact run regenerated identical Rust. New-head cross-host CI remains a
separate publication gate, tracked by exact run IDs in SUB-579.

## Next connected scope

Bind original shared updater `0x40aeae`: its eight-byte EH4 local allocation, real lock-5
acquire/cleanup, `0x40aefb` byte-copy/reference body, validated epilog and RET12.
Keep PTD publication already performed by the caller distinct from later global
publication. Reuse canonical storage, actual pointer fields and existing lock,
copy and registry machinery. Non-null release and exceptional effects require
their own supported contracts; they cannot be replaced with success callbacks.
Sol can begin this bounded integration; no new architectural uncertainty currently
requires Astra.

Original hello, case-19 and other Windows timeout causes remain unresolved. Green
`c0d42a7` workflows do not erase those failures or establish a diagnosis. No merge,
formal approval, release, deployment, XP/7 or general-utility support follows.
