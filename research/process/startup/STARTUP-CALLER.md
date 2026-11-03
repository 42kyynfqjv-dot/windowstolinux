# Original caller after initializer completion

This records the reviewed dd255f2 boundary. The subsequent connected array
execution and current rejection are documented in [C-INITIALIZERS.md](C-INITIALIZERS.md).

## Historical executable boundary

Under the existing explicit native platform and ACP 65001 profiles, the unchanged
authored PE still completes its 16-entry initializer table (12 non-null callbacks,
four null initializer entries). Original caller execution now continues through:

* POP ECX at `0x401632`, consuming the actual initializer argument;
* the AL test and conditional failure branch;
* XOR BL,BL and the local byte store without manufacturing unknown upper bits;
* the original active-scope store from -2 to 0 at `0x401640`;
* CALL `0x401647 -> 0x401913`, including the real flag helper at `0x4021bf`;
* recording that helper's result and the original live startup-state checks;
* changing startup state `0x41cc7c` from 0 to 1 and pushing the original C-array
  bounds `0x415158` then `0x41513c`.

The next rejection is **before CALL `0x401673 -> 0x406ccc`**. Its array arguments,
state 1, scope 0, local writes, outer frame and protected return remain live. No
C-array callback, failure cleanup, outer epilog or normal application return is
substituted. This is original-entry component execution, not full startup,
formatter, rcedit or default converter admission. There are zero new whole-PE
Windows/ELF comparisons.

## Frame, phase and control

The post-initializer entry validates the same live process/image/initialization,
normal-frame identity, registry epoch/top, saved state, cookie, predecessor,
stack pointer, argument 1 and inactive scope. The connected production component
calls it directly after the original initializer's protected CALL/RET succeeds.
It does not acquire this authority from a supplied result or numeric return PC.

The original POP consumes the argument; later phases cannot consume it again.
The scope store additionally requires the actual old value -2, actual new value 0,
correct frame slot, and immutable original scope header/first-row bytes. Local
and global stores revalidate their actual destination identity and live frame
before and after writing. Scope0 represents an active scope; it grants no handler
execution, cleanup completion, restoration or retirement certificate.

Conditional instruction effects remain emitted. Initializer AL0 reaches an
explicit rejection at `0x40178e` before local/scope writes. Unknown AL retains
unknown flags and rejects at branch selection after POP. Startup state 1 reaches
the same original failure target, while a distinct nonzero state reaches the
unbound existing-state branch at `0x4016ac`. These are not synthesized failure
returns, completed cleanup or guessed reentrant success.

Replay checks cover all 25 declared caller cases. After an instruction consumes
the argument or changes scope, entry phase checks reject a second continuation.
Earlier validation/code failures have no new guest effect to repeat. Tests
require unchanged registers, tags and observed memory on retry. They also reject
stale initialization, code lifetime, changed cookie/frame, already-active scope,
argument/control aliases and altered source/data.

## Live guard and unproved thread path

The original `0x4021bf` body actually reads `0x41d2f0`, compares it with zero,
executes SETNE AL and returns through the protected call mechanism. The value is
not forced by the native profile or replaced by a constant. Unknown or typed
flag fields reject; no numeric pointer authority is inferred.

For a zero flag, the original caller's JZ reaches XOR AL,AL; POP ESI; RET. The
actual-entry test demonstrates this branch for the unchanged input, then reaches
the next C-initializer call. Nonzero and unknown values are separate adversarial
component cases. The nonzero path rejects **before FS:[0x18] at `0x40191d`**.
It does not acquire a TEB, guess StackBase from ESP, execute LOCK CMPXCHG or
silently report lock success. The complete original 50-byte body remains
byte-bound, including the currently unexecuted instructions.

This remains the existing single guest thread/exclusive initialization domain.
A future implementation of the nonzero path needs actual owned thread/TIB stack
state, lock identity, reentry and concurrency semantics. None is inferred from
the zero branch or from prior supplied CONTEXT/TEB component observations.

## Evidence and scope of tests

Independent [expectations](evidence/startup-caller-expectations.json) were frozen
before implementing this slice. The 25 post-initializer cases use the real
prolog instructions and checked protected CALL/RET machinery, but their
initializer results/flag/state variations are explicitly declared inputs.
The test preparation is emitted only under cfg(test); it does not replace
initialization in the connected original-entry path. That entry test retains
its established declared CPU and entropy context alongside the bound runtime
producers. It is not a fresh independently measured launch or whole-PE native
execution. The live flag/state branch values are not supplied after entry.

Cases cover normal and partial-known AL, fully opaque EBX, AL0/unknown, live
flag0/nonzero/unknown/typed, startup state 0/1/2/unknown/typed, stale code/init,
wrong argument/frame/cookie/scope, changed caller/helper/flag/scope bytes, a
read-only global write and duplicate protected-return metadata. They check exact
rejection points, prior local/scope/state effects, saved/control identity, array
argument order and preservation of unknown register bits. All 25 replay attempts
must reject without further observed writes or control changes.

The whole input remains the authored PE SHA256
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`.
The replay separately matches caller, lock helper, flag helper and scope bytes to
that unchanged artifact. Five previously recorded Windows wrapper comparisons
remain component evidence; these 25 cases are not new Windows observations.
Final local checks passed: 182 root, 316 CRT, 185 unwind; both artifact checks/full
replay; 89 startup Python (one skip), 106 tools Python, 18 corpus Python (one skip);
all-target Clippy and formatting. Fresh re-emission advanced mtime and retained
identical Rust SHA256
`e44ae7b5550cb85d09336277c05b1724a6a77fae78bfea25fd6c947c65ba5230`.

[Evidence, source hashes and reproduction](evidence/startup-caller.json).

## Review and remaining work

Review of `246087c` rechecked both original exit-table bodies, distinct table
identity, cookie bits, partial stores, no-op cleanup, repeated initialization and
live-frame preservation. Its existing coverage is retained. No source/runtime
defect was demonstrated. One new negative-test oracle initially expected an
unknown-value error at TEST; the actual original TEST preserves an unknown ZF,
and the following JZ rejects. The expectation now checks that exact point; no
runtime gate was relaxed and failed local output is retained.

All three reviewed `246087c` workflows passed: PR Rust 41295706231,
push Rust 41295702763 and startup 41295702770. New-head workflows are separately
tracked in SUB-579; a queued/running workflow is not a pass.

The next C initializer array has seven entries: NULL, `0x40155a`, `0x401605`,
`0x404510`, `0x4109ba`, `0x40c109`, `0x4127b0`. The subsequent C++ array has
NULL and `0x40160d`. Do not assume either array empty. Next scope is shared guarded
array traversal and actual callback/error effects with the current active scope
and startup state retained. Sol can start that inventory/integration. A concrete
nonzero TEB/CMPXCHG ownership requirement may warrant bounded Astra reasoning;
that unproved path remains rejected meanwhile.

Onexit draining/freeing, malloc errno/new-handler, exceptional EH4 cleanup,
actual Windows delivery/containment/collided unwind, native close/EOF and broader
resource/encoding/XP7 equivalence remain unsupported. Historical original-Windows
hello, corpus, output-probe, case19 and other launch timeout causes remain
unresolved; later passing runs do not diagnose or erase them. No timeout, stack,
proof or resource limit was increased.
