# Original post-argv helpers and opaque SLIST initialization

## Connected boundary

Under the existing explicit native startup profile, the original first C
initializer now consumes the argv call arguments, tests the result, executes
`0x401bc9`, queries the live flag through `0x401c1f`, conditionally executes
callback encoding `0x4066b0`, and executes both original RET0 helpers. The FP
wrapper executes its three real pushes. Execution rejects **before CALL
`0x401be4 -> 0x4076a0`**, with arguments `(NULL, 0x10000, 0x30000)` still on the
owned stack. No floating-point control effect or successful return is supplied.

The actual argc/argv publication and its allocation remain intact. This is
guarded original-instruction component execution, not whole-PE conversion,
default admission or full startup/rcedit support.

## Shared SLIST contract

The original IAT `0x415030` identifies `kernel32!InitializeSListHead`; the original
wrapper passes the aligned image-backed header `0x41cca0`. The native adapter
validates that import, process image, initialization lifetime, active protected
call, saved registers, stdcall4 ABI and destination before effects. The general
effect accepts owned writable, aligned eight-byte Module storage, independently
of the application's name or hash. Stack/FILE/lock/errno aliases, incomplete
control-tag overwrites, stale capabilities and unsupported roles reject.

Microsoft documents the header as **for system use only**. Therefore no private
byte pattern is fabricated. Initialization records a new process-owned empty
header identity and atomically forgets the eight private bytes, expiring prior
read facts. Raw guest loads, stores and copies of this live opaque header reject.
Reinitialization replaces its generation without changing the allocation
identity; releasing its storage invalidates the role. Adjacent bytes are intact.
There are at most 32 tracked headers in this serialized startup domain. Capacity
exhaustion rejects before effects; it is not represented as a Windows API error.
SLIST insertion/removal/query calls are not implemented by this binding.

The void API makes volatile return registers, flags and LastError unknown. It
does not assert EAX=0, nor grant callable authority from a header or encoded word.
The original callback encoding remains ordinary scalar computation using the
live cookie and actual original rotate/XOR/store instructions. Partial knowledge
stays partial; no callback is invoked by this checkpoint.

## Requirement provenance and observations

Primary contracts consulted:

- [InitializeSListHead](https://learn.microsoft.com/en-us/windows/win32/api/interlockedapi/nf-interlockedapi-initializeslisthead), retrieved bytes SHA256
  `4177cd2d6d2e4e8572cb07d86668d13631b5d4f5db9ed0e164953d4028e31ab7`.
- Microsoft's [win32metadata SDK header](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h), retrieved bytes SHA256
  `d66df443218279ed2ffe7718b5347e64bf712dbfa5d25a3b0692787169405c69`.
  Its x86 eight-byte layout includes private CpuId state. The URL is moving;
  the hash identifies the exact reviewed bytes, not a pinned SDK release.

[Frozen expectations](evidence/post-argv-expectations.json) precede implementation.
The authored [Windows probe](observe_slist.c) tests 12 aligned PE32 cases over
independent input patterns/offsets. It records private bytes observationally,
checks empty depth/pop and guards, and never executes a misaligned or unsupported
operation. Its [runner](observe_slist.py) retains raw output before assertions,
pins the existing CI MSVC 14.44 configuration, and preserves timeout output.
The protocol-only tests use synthetic records and are not Windows observations.
First Windows run 41344214535/job124960453455 retained artifact13098681056:
MSVC C4127 on a constant sizeof condition, promoted to C2220 under /WX. No probe
executed and its dependent jobs were skipped. The layout requirement now uses
a compile-time typedef, retaining /W4 /WX. Corrected run **41344469225**,
job **124961233509**, artifact **13098128613** now supplies 12 actual PE32
observations. Source hash matches published 0d5f8c6; PE machine I386, PE hash and
raw report hashes were independently checked. The [raw rows](evidence/slist-windows-0d5f8c6.jsonl)
have SHA256 `7dbeb5ab0c9c8e9b6fd63bd7b03c5375aa5c8e39ef1d3250bfef7e0ef881562e`.
All tested initialized bytes were zero on that host; the native contract still
keeps private bytes opaque and does not generalize that observation to XP/7 or
other implementations. The [original compile diagnostic](evidence/slist-msvc-a4d382b.stdout)
is retained separately. These are API component observations, not translated
Windows/Linux pairs. The rest of the corrected workflow remains a separate gate.

## Verification and review scope

[Evidence](evidence/post-argv.json) records final local test/replay hashes and CI
status. Final local aggregates pass 182 root, 337 CRT and 185 unwind checks;
both ignored CRT artifact gates execute in the full replay. Python has 101
startup tests (one skipped), 106 tools and 18 corpus (one skipped). Clippy
warnings denied and formatting pass. Full replay passes five retained original
Windows wrapper comparisons. Same-input independent emission matches Rust
SHA256 `52a24b83593945e60cd7096a3f7373e4b1867dd9df5cde3bf559ecb45905af63`.
The frozen original PE hash is unchanged. Fifteen original-helper cases cover live flag/unknown rejection, cookie
encoding with partial knowledge, exact FP rejection and changed bytes in each
helper. Eleven direct API cases cover success, ABI/register/return-token errors,
unknown argument, expired image/init/provider/storage, cross-thread access and
duplicated protected returns. Independent opaque-state cases cover read-fact
expiry, adjacent storage, reinitialization, permissions, stale/foreign/partial
control aliases, errno overlap and capacity-before-effects. The complete replay
must execute both named SLIST checks, not infer them from a separate aggregate.

An aggregate run and isolated reproduction exposed a stack-layout regression:
putting 32 new header records inline in every runtime overflowed three existing
512 KiB native test children. The fixed-capacity table is now boxed once at runtime
creation, keeping API bookkeeping allocation-free and the same capacity. One numeric fixture still overflowed in an aggregate despite an isolated pass.
Its two independent runtime lifetimes now use separate non-inlined test frames,
with all 21 vectors, stale checks and special authority/unknown checks unchanged.
Stack limits, test cases and semantic gates are unchanged. Failed logs and both
interrupted replays are retained separately; only final-source reruns count below.

The preceding decf589 source fingerprints were verified against its published
files, and all three exact-head workflows passed (41341194171, 41341190130,
41341190135). The retained 158-row conversion trace remains separately
hash-verified; no new parser/allocator Windows result is inferred.

The first test attempt expected the wrong *rejection diagnostic* for an unknown
flag word (`unknown ZF` rather than the earlier `unknown scalar bits observed`).
That expectation was corrected; the memory read and rejection were preserved.
No semantic acceptance gate or timeout limit was relaxed. An initial independent
repeat command selected the existing synthetic Main-fill fixture by omitting
W2L_EH4_CODE; its different generated hash was expected. A second command failed
before native execution because its output directory was missing. Both logs are
retained. Repeating with the same original code catalog/vectors, PE and an
existing fresh evidence directory passes and produces identical Rust.

Read-only inventory identifies wrapper `0x4076a0` calling `0x40d000`. The first
new instruction is waiting FSTCW (`9B D9 7D F8` at `0x40d00b`); later operations
include FLDCW, waiting FSTCW and conditional STMXCSR/LDMXCSR under the live
feature flag. Original control-mask validation and invalid-parameter/errno paths
also need preservation. This is not another no-op helper.

Next validate the original FP-control callee and its reachable helpers, define
guest x87 control/status and MXCSR knowledge separately from host state, and bind
only justified effects with independent preservation/error tests. Existing
FNCLEX support does not imply control-word or SSE support. Resource-failure
equivalence, nonnull free, exceptional cleanup, XP/7 and other dependency-map
limits remain open. Five retained Windows wrapper comparisons and 158 retained
Windows conversion API rows are component evidence; **zero new whole-PE pairs**.
All historical original-Windows process timeout causes remain unresolved.


## Exact-head stack regression follow-up

Final-head inventory run **41345071064**, job **124967900133**, failed the word
register test's generated child with a stack overflow (336 passed, one failed,
two ignored). The earlier local aggregate pass did not establish CI resolution.
The two Rust workflows passed; the inventory failure remains preserved.

A controlled local reproduction retains the same 512 KiB limit and adds 32 KiB
of environment padding. It fails before the fix and passes afterward. Previously
the fixture returned its large runtime/CPU tuple by value through another case
frame. A non-inlined fixture now owns both and lends mutable references to each
case. Selected compiler prologue sizes drop from 77,512 + 146,040 bytes to
40 + 108,680 bytes; these are selected frames, not total peak-stack measurements.
All 152 cases and assertions, including final checked==152, remain. The same
binary also passes with 64 KiB environment padding and the unchanged stack limit.
CRT337/unwind185, Clippy and formatting pass locally. New CI must verify the new
head; this is unrelated to the unresolved Windows process timeout history.
[Evidence](evidence/word-stack-review.json).
