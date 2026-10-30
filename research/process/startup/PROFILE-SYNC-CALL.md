# Native-profile synchronization call and original constructor return

## Executed boundary

The opt-in `w2l-native-sync-20348-v1` component now executes the original indirect
CALL at `0x402c61` using the existing native synchronization implementation.
The original constructor returns through its decoded epilog and RET. The original
loop publishes count `1` at `0x41cd04`; the single lock at `0x41ccec` has the same
mapped allocation and owner as before the call. The index is checked against the
original loop's table role; it is not chosen from a free native slot.

Execution next rejects the original FLS acquisition call
`0x4024d6 -> 0x402963`. Both module/function caches, the constructed lock and the
published count remain live at that rejection. Neither FLS publication nor full
startup completion is issued. Default admission still stops at LoadLibraryExW
`0x402b00`. No production admission rule was relaxed.

## Observable contract versus internal limits

| Requirement | Contract and implementation |
| --- | --- |
| Actual callable target | Original guard and single-use receipt, named export publication, source and target lifetime are checked before the existing native operation. Descriptors alone cannot execute. |
| Arguments and object identity | Three initialized arguments; flags zero; aligned writable 24-byte mapped object with no protected alias. Pointer authority comes from the canonical image, not a retagged allocation. |
| Construction and return | Native fixed storage actually constructs the opaque object; a nonzero result then flows through protected stdcall cleanup of 12 bytes and the original constructor/loop. No supplied API success callback is used. |
| Recursion and deletion | Existing single-thread recursive ownership and deletion contracts are reused. Held-object deletion, stale leases and duplicate deletion reject. General concurrent contention is outside this component domain. |
| Native resources | 32 object slots and 32 recursive leases are reserved in fixed storage. Capacity, alias, malformed flags and stale authority reject the component domain; they do not return guest BOOL zero or invent LastError. Allocation-denied tests cover the native operation and full capacity. Bootstrap and unrelated runtime collections are not claimed allocation-free. |
| Error ordering | Invalid profile/call state rejects before construction. Prior objects, caches, guest bytes, return slot and LastError remain intact. Successful construction makes lock bytes opaque and LastError unknown. |
| Windows low-resource failure | Still unclosed. Microsoft's BOOL-zero/GetLastError contract does not specify one universal allocation error or failed-object byte state. Native free capacity cannot establish original Windows resource availability. |

This is executable **native-profile component semantics**, not proof that the
profile matches every possible Windows execution. A Windows equivalence claim for
this successful path remains conditional on original successful construction;
that premise has not been inferred from native capacity. Whole-program admission
must either establish a supported environment/resource relation or implement and
validate the required Windows failure relation. The existing Windows success
observations cannot discharge that obligation. No failure is silently converted
to successful guest execution.

Primary contract:
[InitializeCriticalSectionEx](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsectionex).
The observed mapping revision is Windows 10.0.20348; it is not an XP/7 guarantee.

## Review and regression evidence

Review reproduced a failure-ordering defect in the shared stdcall adapter: a
changed callee-saved register rejected in `finish_pop` only after construction.
The pre-fix test fails because the previously readable object has become opaque.
The adapter now checks callee-saved registers before the effect, alongside its
existing return identity, stack and cleanup checks. This changes rejection timing
for malformed call state; it does not erase valid earlier guest effects.

Twelve independent native-profile cases assert exact success or rejection and
poststate: normal construction/recursion/deletion/reinitialization, changed target,
capacity index, unsupported flags, wrong cleanup, corrupted return, corrupted
callee-saved state, unloaded provider, incomplete publication, wrong thread,
occupied slot with a distinct prior object, and protected alias. Existing allocator
denial/full-capacity, sparse reuse, partial construction and protected RET tests
remain mandatory. The unchanged-entry cases assert actual lock count and recursive
ownership at the FLS boundary. Existing changed-code/guard-target cases remain.

[Machine-readable evidence](evidence/profile-sync-call.json) records source hashes,
local validation and the retained recorded-Windows comparison. These five wrapper
comparisons test prolog/epilog components; they are not new synchronization Windows
observations or whole-PE Windows/ELF executions. Historical Windows timeouts and
full formatter/startup/rcedit support remain unresolved.

## Next connected scope

Bind the original FLS acquisition body at `0x402963` to the established process-slot
and fiber-value ownership machinery and the actual resolver/export implementation.
The next inner allocation is `0x402968 -> 0x402b3e`, with callback
`0x4028a7`; original publication then calls `0x402981 -> 0x402bef`. Existing
`fls_allocation_result` only records an independently supplied outcome, and the
current component uses supplied index 7. It is not an allocator.
Retain constructor effects if FLS allocation or publication fails; validate callback
ownership and original cleanup before allowing startup to continue. Do not reuse a
supplied component slot/result as evidence of actual allocation. Sol can review this
slice; escalate only a concrete FLS allocation/lifetime or callback contract gap.

Validation: 280 CRT tests passed, both artifact-dependent tests passed in replay,
75 Python tests passed (one existing skip), and Clippy/format passed. All three
128598e workflows (41059104174, 41059094604, 41059094730) and all three 4ee74c7
workflows (41057500037, 41057487928, 41057488149) completed successfully. Changed-head
CI is a separate gate; these predecessor outcomes do not validate the new commit.
