# Original FILE scope and the remaining formatter effects

This is a connected component boundary in SUB-579 / PR #45. It adds no complete
startup, formatter or rcedit admission. The formatter driver remains an explicit
cut supplied by the native component harness. Runtime rejection of that cut is
not a replacement for guest exception delivery or termination.

## Instruction-derived work

`FileScopeProof` checks the complete original normal wrapper suffix, lock and
unlock leaves, normal cleanup entry and EH4 epilog. It derives the result local
and checks that it lies inside allocated locals, outside saved registers, guard
and registration metadata. The critical-section member is the checked FILE's
offset 32. Import identities are separate prerequisites; the evidence checker
verifies the original IAT entries are `KERNEL32!EnterCriticalSection` and
`KERNEL32!LeaveCriticalSection`. There is no application-name/hash dispatch.

The emitted sequence uses the existing arithmetic/operand emitter and shared
protected CALL/RET machinery. The latter now has a lock-independent activation
primitive: acquiring a lock cannot require a fictional preexisting lease.
Existing stream calls still check their lease before delegating to it.

After the actual prolog has installed its record in `NormalCallEpoch`, the
wrapper executes the original result initialization, lock, state-zero activation,
driver CALL, result preservation, state -2 store, normal cleanup CALL, result
reload and checked epilog. Lock/unlock leaves execute their original instructions;
only their validated import effects use the owned runtime lock contract. Recursive
acquisition releases its own depth, retaining any outer lease. A void API return
does not manufacture known EAX/ECX/EDX or arithmetic flags.

The component domain requires an initialized, exclusively owned, uncontended
critical section on the current thread, with live storage and bounded recursion.
It does not cover Windows deadlock exceptions, contention, abandoned owners,
asynchronous delivery or startup construction of the original lock object.
These are premises of the component, not conclusions from successful samples.

The driver cut receives the real child activation and held lease. It must execute
its protected RET and preserve the lock stack, active scope, saved values and
registration. Unknown effects fail closed and retain reached storage/CPU effects.
No host RAII destructor releases the lock on an error. Neither scope reset nor
normal epilog runs after an unresolved body error. The unwind entry that first
reloads ESI from the frame is explicitly outside this normal-entry certificate.

## Independent cases and provenance

Three new Rust test functions cover:

- Five independent return values (0, 1, 93, signed minimum bits and all-one bits),
  original instruction execution, a recursive outer lease, scope/result-local
  state at the call, an externally visible body write and exact stack retirement.
- Six invalid compositions: mismatched lock/cleanup arguments, uninitialized
  lock, unresolved body effect after a write, body changing scope state, body
  releasing the lock, and success without the protected RET. Failure must preserve
  reached effects and poison the registry without fabricated cleanup.
- Seventeen byte/shape negatives for scope/result ownership, call targets,
  partial/changed operations, lock member, truncation, argument cleanup and an
  unwind entry substituted for normal cleanup.

The normal-wrapper evidence job extracts these new regions from the unchanged
current-run PE and checks its import names. Both hosts execute the three native
test functions using those bytes. **These are native component tests with a
supplied driver, not additional original-Windows differential pairs.** The five
preexisting observer-versus-native helper/epilog comparisons remain separately
reported, with identical PE and emitted-Rust hashes required across hosts.
Zero new whole-PE comparisons are claimed.

## Precise remaining exception/termination contract

The retained authored image establishes these dependencies, independently of
whether its ordinary printf call happened to fail:

1. The FILE wrapper activates EH4 state zero at `0x404677`, calls the formatter
   driver at `0x40467e`, then normally resets state and calls cleanup. Its EH4
   unwind entry is `0x4046a8`, while the normal cleanup call targets `0x4046ab`.
   They cannot be interchanged: the unwind entry additionally restores ESI.
2. Driver `0x4052ba` constructs formatter state, calls the parser, destroys its
   buffer and restores temporary buffering. The existing individual graph proofs
   do not yet compose all those calls under a live C++ registration.
3. The integer dispatcher uses C++ FuncInfo, not EH4. Its state-zero unwind map
   names `0x4026fc`, which jumps to `0x40770c`. This is a termination dependency,
   not the FILE unlock action. Relabeling C++ state zero as EH4's inactive -2
   would erase an observable control-flow effect.
4. `0x40770c` calls the PTD getter `0x40a2e1`, reads the callback at +12 and may
   call that callback after a separate validation call. The getter itself calls
   `0x40a332` and branches directly to `0x4077ff` on a null result. A nonnull PTD
   or null callback alone therefore does not prove ordinary return.
5. `0x4077ff` has signal/reporting dependencies, a conditional `INT 29h` path and
   a call to `0x407004` with status 3. That helper passes cleanup mode 2 to the
   shared exit path. Substituting normal shutdown/flush, dropping a callback, or
   returning a synthetic formatting error is not justified by current evidence.

The next connected gate is the driver/parser/integer activation composition:
bind initialized formatter/context/varargs and the current thread's PTD, prove
all reachable calls and fault conditions for the bounded format grammar, and
either discharge a complete no-escape certificate or execute the original C++
dispatch/termination effects. A selected happy-path trace, a formatting result,
or the normal FILE scope certificate cannot supply that certificate. The smallest
required exceptional cases distinguish failure before lock acquisition, a body
escape with the FILE scope active, C++ state-zero unwind into termination, a PTD
getter failure, and a returning/failing registered termination callback. Until
those effects are closed, full conversion must reject before emission.

Primary contracts: [EnterCriticalSection](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-entercriticalsection),
[LeaveCriticalSection](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-leavecriticalsection),
[terminate](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/terminate-crt?view=msvc-170),
[internal CRT functions](https://learn.microsoft.com/en-us/cpp/c-runtime-library/internal-crt-globals-and-functions?view=msvc-170),
and the original byte/metadata evidence in `formatter_binding.py`. Independent
Rust implementation; no Wine or proprietary source import and no clean-room claim.

## Prior checkpoint and failure evidence

For `6cb18d40133e17602d3b97b635564ac697bb420c`, dedicated CI 40694121946 and
full CI 40694121953 succeeded. The dedicated artifact records five comparisons
per host, PE SHA-256 `1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`
and matching Rust SHA-256 `4759c444163bec70791d3b7ec5d77e7476f5c216e1ac92dc4597c15c321a7fea`.
This confirms the CRLF vector fix under fresh Windows/Linux CI.

Parallel full run 40694131051 failed the original-Windows `untaken` imported-output
fixture after 15 seconds. Artifact 12818461816 preserves the exact executable,
empty outputs, launch record and process observation: 0 CPU seconds, loaded CRT,
one observed thread, no detected wait-chain cycle. The measured PE hash is
`b5a3bb8ee10c6ca16d5b9b2b53e39bc214d6fc4a6e6977a1fdf20a7dc7675554`.
These observations do not establish a loader, runner or application cause. The
failure remains unresolved; a concurrent pass is not a fix. No retry, raised
timeout or removed check hides it. Historical timeout evidence remains separate.
