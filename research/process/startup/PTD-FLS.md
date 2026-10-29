# Original PTD normal-path continuation and FLS boundary

This is a connected **component**, not whole-PE admission. The retained authored
MSVC PE is unchanged (`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`).
`check_normal_wrapper.py` checks its actual helper/getter/thunk bytes and import
identity against the native test inputs. No proprietary source is imported.

## Corrected dependency identity

The import at `4150a0` is `kernel32.dll!FlsGetValue`, and `4150a4` is
`FlsSetValue`. The optional dynamic function name at `416724` is `FlsGetValue2`.
The earlier TLS/FLS description was too loose: the fallback is FLS, not TLS.
[Microsoft's FlsGetValue contract](https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsgetvalue)
assigns each index a separate value in each calling fiber. A thread-only identity
would permit the wrong object after a fiber change. The public contract does not
promise that successful lookup preserves or zeroes LastError. The implementation
therefore makes that knowledge unknown; the original getter's GetLastError and
SetLastError calls perform the save/restore. The dynamic alternative is rejected.

`CrtFiber` binds one stationary fiber context to the runtime and thread.
`CrtFlsSlot` additionally binds index and allocation generation. These constructors
accept **explicitly established component input state**; they do not execute or
prove original FlsAlloc, fiber switching, destructor callbacks or lazy creation.
Reads revalidate the complete live PTD root and prefix. Null and the original
initializing sentinel `ffffffff` are distinct allowed values; arbitrary numbers,
unknown bits, wrong roles, offsets, foreign runtimes and retired objects reject.
Reusing an index does not renew an old slot token. Retiring a fiber requires no
live slots and invalidates the cached canonical errno binding. Callback/destructor
execution and general fiber switching are not implemented by these transitions.

## Distinct continuation ABI

The original getter at `40a332` calls prolog `414268` and epilog `414254`, with
handler `414ad6`. It cannot use the manager EH4 prolog certificate. Let `S` be the
getter's entry ESP and `N` the preceding pushed local-byte count:

| Word/state | Address after prolog |
| --- | --- |
| Original outer return | S |
| Saved EBP / new EBP | S - 4 |
| Scope level, initially -1 | S - 8 |
| Handler | S - 12 |
| Previous FS head / record | S - 16 |
| Saved EBX, ESI, EDI | S - 20 - N, S - 24 - N, S - 28 - N |
| Cookie XOR EBP / body ESP | S - 32 - N |
| Moved helper continuation before RET | S - 36 - N |

The certificate validates the entire helper protocol with parameterized code and
cookie addresses, complete ranges and nonaliasing. Shared instruction lowering
executes arithmetic, register moves and stack operations. The one specialized
transfer removes the old protected continuation's authority immediately before
the certified instruction overwrites that source word with -1. Both copies must
match the same fresh call identity; the final RET must consume its only remaining
copy. Any register that retains that consumed token is reduced to the original
numeric continuation PC; ECX does not retain reusable return authority. This is not a general override of cdecl CALL/RET validation.

The epilog moves its own fresh continuation through ECX, restores FS, discards the
guard, pops saved registers, restores ESP/EBP and pushes the continuation for RET.
Only after exact restored state is checked are abandoned record words retired.
Guard validation is a supported-domain check, not an invented guest guard call.
The normal component uses a borrowed incoming thread-head token and a byte-backed
record projection. **It does not register this different handler with the live
exception dispatcher or establish incoming-chain containment.** Exceptions, stack
growth and callback unwinds through this record remain unadmitted.

## Connected execution and evidence limits

The original errno router can invoke the actual PTD getter with its protected child
call. The getter executes its original branch, scope store, FLS thunk, sentinel
normalization, LastError restoration and epilog before returning to the original
errno selection. The selected live cell becomes canonical without initializing
unknown bytes. No output or errno answer is selected by a binary hash/name.

Five Rust tests compile and execute native cases and mutate helper/thunk protocols:

- Existing PTD and initializing-sentinel paths; null, invalid/mismatching index,
  dynamic-function and unknown-mode paths reject rather than invent acquisition.
- Four local-frame sizes with independent expected word addresses; guard, saved
  register, chain, frame-pointer, thread and protected-slot corruption; replay.
- Every fixed helper/thunk byte mutation, overlapping code/data and relocated
  helper/cookie addresses.
- Fiber/runtime identity, slot reuse, unknown/forged values, incomplete pointers,
  retirement, unknown PTD bytes and canonical errno invalidation.
- Connected errno → PTD → FLS → original return for PTD, sentinel fallback and
  unknown errno bytes; original LastError and canonical write coherence.

These are native component cases, **zero new Windows observations and zero
whole-PE translation pairs**. The older five recorded Windows wrapper-boundary
comparisons remain separate. No successful sample closes the unknown branches.

## Remaining connected gates

1. Bind the new record projection to actual live registry ownership/exception
   dispatch, including handler `414ad6`, before using it in the registered manager.
2. Execute actual index/fiber acquisition and lazy `40a1ee`: initializing sentinel,
   `calloc(1,0x364)`, recursive errno, failed setter, cleanup/free and PTD initializers.
   Null lookup currently reaches an explicit unbound-effect rejection after prior
   FLS effects; it is not falsely returned as a successful null PTD acquisition.
3. Establish dynamic `FlsGetValue2` resolver/target and any different error effects.
4. Retain encoded new-handler/guard/callback, free/error mapping, locale/FILE,
   actual exception delivery and outer startup gates in REMAINING-CALLBACKS.md.

Sol can review this bounded normal path and connect further evidence. The next
semantic decision is how the different record/continuation ABI participates in
live registry delivery and recursive initialization, not another arbitrary opcode.
Historical Windows timeouts remain unresolved. The separately diagnosed aggregate
projection budget remains subject to its unchanged deadline and full case set.
