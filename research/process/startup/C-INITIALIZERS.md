# Original guarded C-initializer array

## Executable boundary and evidence

The unchanged authored PE, under the existing explicit native-platform and ACP
65001 profiles, now calls the original array walker at `0x401673 -> 0x406ccc`.
It skips the first null word, executes the original indirect guard and CALL, and
runs the first callback's original setup instructions. Actual stores set app
kind `0x41cd38=1`, file mode `0x41d2bc=0x4000`, and commode `0x41ce84=0`.
The original onexit initializer with argument 1 writes six UINT_MAX sentinels to
`0x41cc88..0x41cc9c` and publishes byte `0x41cc85=1` last. These tables are
**distinct from** the earlier cookie tables at `0x41ce88/0x41ce94`.

Execution rejects **before FNCLEX at `0x40158a`**. Startup scope 0, state 1,
array arguments, original caller/array frames, and prior effects remain live.
There is no synthesized callback return, later callback execution, cleanup or
complete startup. Current `CrtCpu` models GPRs, integer flags and XMM lanes, but
has no x87 status/control/tag state; treating FNCLEX as a no-op would erase an
observable effect. Default conversion and full startup/formatter/rcedit remain
unsupported. There are **zero new whole-PE Windows/ELF comparisons**.

[Independent expectations frozen before implementation](evidence/c-initializer-expectations.json)
and [reproduction inventory/results](evidence/c-initializers.json) distinguish
original-entry execution, separately declared arrays, native negative tests and
the five retained recorded original-Windows wrapper component comparisons.

## Complete frozen array inventory

The immutable array is `0x41513c..0x415158`: NULL followed by these six targets.
All bodies and the walker are bound to their original PE address and byte hash.
The subsequent C++ array `0x415130..0x415138` contains NULL and `0x40160d`.

| Order | Target | Actual body / support boundary |
| --- | --- | --- |
| 1 | `0x40155a` | Setup prefix and onexit initialization execute; FNCLEX rejects. Remaining body is inventoried, not executed. |
| 2 | `0x401605` | Original option getters and OR/stores, XOR EAX,EAX and RET execute in separately declared arrays; not reached in normal entry order. Unknown high words remain unknown. |
| 3 | `0x404510` | FILE pointer-array allocation/free, lock and descriptor/FILE composition; explicitly rejects. Static inventory is not an observed normal-path failure. |
| 4 | `0x4109ba` | Locale epoch wrapper; explicitly rejects until connected with the current runtime epoch. |
| 5 | `0x40c109` | Original default-filemode conditional store and RET execute in separately declared arrays; not reached in normal order. |
| 6 | `0x4127b0` | Stores the **full raw BOOL** from IsProcessorFeaturePresent(10); explicitly rejects. Existing predicate-only CPU observation returns synthesized 0/1 and cannot silently authorize this consumer. |

No original source, configuration or PE is tuned to reach later callbacks.
Declared test arrays exercise the generic traversal and supported original
bodies independently; they are labeled modified-array component inputs.

## Guard, lifetime, failure and return contracts

The bounded walker accepts an immutable same-image, aligned array of at most
64 words. This is a supported-domain restriction, not a Windows capacity claim.
It executes original iteration, null skipping, guard and indirect-call
instructions. Guard receipts are internal, bound to current cursor/target and
consumed once. Duplicate target addresses are called separately in order.
Actual child CALL/RET validates protected return and saved-register restoration.
Arguments, live code, table identity and lifetime are checked again after each
callback. Callback success is not supplied by a data certificate.

An exact full-width nonzero EAX stops traversal and returns unchanged, including
`0x80000000` whose AL is zero. Unknown or pointer-typed results cannot decide
success. Callback writes survive later rejection. A new regression demonstrated
that ending initialization inside a callback could otherwise permit the next
callback; post-call initialization validation now rejects before advancement.
Runtime limits and generic decoder rejection of unbound indirect calls remain
unchanged. Only the explicitly bound original graph lowers this call form.

Native coverage includes 28 declared traversal cases plus 28 replay rejections,
12 separately declared original-callback cases, and 16 constructor/onexit/mode
cases. They require explicit expected-success or precise failure and check prior
writes, rather than counting any rejection as success. Cases cover empty/null
arrays, duplicates/capacity, mutated code/guard/IAT, wrong extents/arguments,
unknown returns, missing/corrupt RET, stale target/table/initialization, and
partial onexit writes followed by protected-slot rejection. The unchanged-entry
case and retained 25 caller cases also check the new FNCLEX boundary.

## Next cohesive implementation gate

A bounded Astra High design pass is justified for a shared x87 environment and
its startup preservation/reset contracts. First inventory all reachable floating
environment helpers in the remainder of `0x40155a`, including control-word and
exception-mask behavior. Define initial knowledge, exact FNCLEX status changes,
control/tag preservation, host isolation and exceptional/failure behavior from
primary instruction contracts. Integrate actual instructions and independently
mutate prior state; do not assume Windows defaults or use a host-only no-op.
Then connect the remainder of this first callback before later callbacks. Sol
can independently review this traversal and routine evidence/CI in the meantime.
The raw-BOOL consumer, FILE/locale composition, full C++ array, non-null frees,
exceptional cleanup, actual delivery/collided unwind, native close/EOF and
broader platform/resource/encoding equivalence remain separate explicit gaps.
Historical original-Windows launch/process-exit timeout causes remain unresolved.
