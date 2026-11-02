# Original first-initializer completion

Independent review of 341de3e found no additional ownership defect in the checked
copy/release domain. The decoded SUB/MOV qualifier preserves original operands,
flags and load order. The local relation retains exact source bounds and rejects
changed arguments, continuation/RET ABI, cursor capability, stale/reused roots
and changed thread/fiber state. Native release validates full allocation ownership
and reserves retirement metadata before storage release; original protected RET
precedes completion validation. Partial cleanup preserves earlier releases.

All 556 predecessor replay source hashes independently match exact commit blobs.
Its five retained Windows wrapper comparisons are component evidence, with zero
whole-PE pairs. Both predecessor Rust CI workflows passed; inventory completion
is a separate gate. No Windows resource-failure equivalence is inferred.

## Connected original execution

The first initializer now executes CALL 0x4015ee to the existing guarded zero
helper at 0x401bbc, then CALL 0x4015f3 to 0x401d4c. The original five-byte thunk
`e9 6b fe ff ff` is validated as JMP 0x401bbc and executes the same helper in the
existing activation. It does not synthesize a new CALL/return slot. Original TEST,
conditional failure edge and RET execute. The fatal path at 0x4015fd remains an
explicit rejection.

The original guarded C array then reaches callback **0x404510**, whose FILE
allocation/lock composition remains unsupported. Both controlled empty and
three-entry native-profile variants verify the actual selected array target,
published vector/string identities, distinct live storage and retired temporary.
No published string points into the freed temporary or wide snapshot.

Four independent continuation cases cover actual zero-helper execution, nonzero
result/fatal-edge rejection, unknown result/unknown-ZF rejection and a corrupted
outer protected return. Failure injections are test-only; production calls retain
exact original helper bytes and target guards. No initializer result is supplied
by a success callback.

## Next bounded scope

Inventory original FILE callback 0x404510 and its allocation, stream-lock,
registration and cleanup dependencies. Reuse canonical FILE/descriptor/heap
ownership; bind only justified original instructions and effects. Add independent
partial initialization and failure-ordering cases before advancing admission.
Sol can perform this inventory and a bounded connection. Escalation is warranted
only if a specific ownership/exception design is unresolved.

Synthetic environments only. Full environment propagation, default admission,
startup/rcedit, Windows resource-failure equivalence, exceptional cleanup and
copy-error termination at 0x407b5f remain unproved. Historical Windows timeout
causes remain unresolved. Final committed-source replay and CI must be reported
for the published head separately from predecessor evidence.
