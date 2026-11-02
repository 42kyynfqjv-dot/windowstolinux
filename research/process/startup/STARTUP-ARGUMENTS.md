# Original environment getter and Main argument preparation

The explicit controlled native-profile entry now executes original instructions
from `0x401700` through `0x401716`, stopping **before Main CALL `0x401717`**.
It reads the existing environment vector, obtains the original argv/argc cell
addresses, loads their live values and pushes envp, argv and argc in that order.
Main has not been entered. Reaching this call is not whole-PE startup admission.

## Original producers and fallback

Getter `0x406c88` loads `0x41ce54` and TESTs it. A nonzero value returns without
rewriting the global or calling an API. For zero it calls original `0x4069df`
and stores the returned value in `0x41ce54` at the original MOV.

The fallback reads `0x41ce48`. If nonzero, it returns that value. Otherwise it
compares the wide-environment cell `0x41ce4c` with zero. When both are zero the
original XOR/RET returns zero; this is an executed NULL branch, not a fabricated
allocation result. A nonzero wide cell invokes the existing original producer
`0x406a0b`, requiring its live native platform and exception-registry context.
Its successful zero status takes the original branch to reload `0x41ce48`.

That producer retains its existing locale, controlled environment snapshot,
conversion, allocation, distinct string/vector ownership and temporary-release
contracts. No second environment model or supplied success callback is added.
The nonzero-status branch calls the still unsupported wide-environment copy at
`0x406b79`; it rejects with the actual child CALL state. No Windows allocation
failure result, LastError or errno is invented to reach or bypass that branch.

Cached getters preserve volatile registers they do not modify. Successful lazy
initialization instead preserves the original producer's effects: the cleanup
POPs put zero in ECX, and API clobbers can leave EDX unknown. A cache read is not
a license to erase these differences. A failed publication to readonly storage
retains the producer result and earlier state; it does not restore an old cache.

## Argument cells and authority

Original getters `0x4070b2` and `0x4070ac` return cell addresses `0x41ce6c` and
`0x41ce68`. They do not manufacture argv storage, argc, or pointer authority.
The caller binds the returned address to the exact live canonical image cell at
the original dereference, then executes MOV ESI,[EAX] and PUSH [EAX].

Payload values retain their types and knowledge. Unknown argc bits are pushed
without becoming known. Moving a previously issued stale pointer preserves its
bits and expired identity; it does not revive the allocation. Numeric address
bits remain scalars. The component may transport these values because the
original instructions do not dereference their pointees. It grants no Main-call
or memory-access authority. Actual later dereferences and any Main admission
must separately establish live bounds and ownership. Protected control values
still reject when an instruction attempts to observe their bits.

On the controlled original-entry path, argv/argc come from the previously
executed two-pass parser and envp from the original environment-table producer.
Both empty and three-entry synthetic variants retain the real vector/string
identities after temporary release. The original normal frame, scope 0 and
startup state 2 remain live. Non-NULL callback-cell validation remains rejected
before this sequence; no callback or exceptional delivery is newly admitted.

## Independent review and evidence

Review of `9464142` found no additional defect in mapped callback-cell provenance,
live NULL decisions, original PUSH/CALL ordering or non-NULL rejection. All
**568** committed replay-source hashes and the final Rust/report hashes were
independently reverified. The replay retains five component comparisons and
zero whole-PE pairs.

Thirty native cases cover cached and lazy getters, actual one/three-entry
production, both-NULL behavior, missing platform, unknown globals and arguments,
stale pointer transport, numeric values without authority, readonly publication,
mutation, expired ownership, duplicate return authority, malformed ABI and a
third-push bounds failure retaining the first two arguments. Repeated calls use
fresh protected activations; replaying a returned getter rejects. Existing
callback/release, canonical, aggregate, Python, Clippy and all 152 low-stack
cases remain gates, followed by a clean commit-pinned replay. Local final gates
passed: 362 CRT tests (two artifact gates separate), 185 unwind tests, canonical
entry variants, 115 Python tests (one skip), Clippy with warnings denied,
formatting and all 152 cases at the unchanged 512 KiB child limit plus 64 KiB
environment padding. Read the tracker and final replay metadata for subsequent
commit-pinned and remote CI outcomes.

### Separate original Windows failures

Predecessor PR workflow `41397991858` and inventory `41397986094` passed. Push workflow `41397986127` failed
in job `125123391898`: original corpus case 26 timed out before conversion.
Artifact `13120022686` and its PE hash were independently rechecked. Its expected
output is empty; the taken entry path skips the write helper and returns zero.
The same PE exited normally in PR artifact `13120251367`. Neither outcome locates
the stalled instruction or explains the failure.

Historical case 1 in run `41378889653`, job `125065106041`, is separate: it printed
C01 and was still alive before conversion. Both retained observers verify owned
process identity and contain modules/WCT records, but **no IP or stack**. Both
children were killed after timeout. Those records cannot retrospectively acquire
missing execution context. The existing observer explicitly does not suspend
threads, debug or read remote memory; no new diagnostic scope is implied here.
No timeout increase, dropped comparison, retry-only fix or root-cause claim is
made. Other historical timeout causes also remain unresolved.

## Next connected scope

Inspect Main's entry ABI and original body at `0x401280`. Bind its three arguments
and live caller return to existing Main/exception/formatter machinery only where
the original instructions and effect contracts justify it. Merely pushing the
arguments is not executing Main. Non-NULL PE/EH4 callback validation, original
exception acquisition/delivery, resource-failure equivalence, concurrency,
default admission and full rcedit remain unsupported.
