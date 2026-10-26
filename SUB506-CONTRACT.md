# SUB-506 bounded calls and returns

Historical call-only contract. SUB-508 replaces the return-only vector with the
unified tagged stack in [SUB507-DESIGN.md](SUB507-DESIGN.md). The exact three
argument/cleanup forms are now supported; call targets, depth and execution limits
below still apply. Prior counts and exclusions below describe the SUB-506 checkpoint.

Support exact unprefixed E8 rel32 in 32-bit mode and existing C3 RET. The signed
relative displacement must be nonnegative; target = checked instruction-end +
displacement, must agree with iced and be an executable instruction boundary.
Decode both the target and continuation even if a path is not executed. All
non-return graph edges strictly increase byte offset, excluding recursion/cycles.
No inferred function boundaries or general calling convention are claimed.

A logical stack begins with an explicit entry sentinel (None). CALL pushes its
continuation (Some offset) and enters the target without changing EAX/flags. RET
pops: a continuation resumes that caller with current EAX/flags; the sentinel
terminates with the existing known-EAX exit range 0..255. Internal returns may
carry arbitrary EAX or unknown state; only actual subsequent reads require known
state. General stack contents/ESP, PUSH/POP, RET imm16, indirect/far calls,
exceptions, imports and memory remain rejected by the instruction/PE whitelist.

Soundness is restricted to this closed instruction set: only CALL/RET can touch
stack storage, so balanced return addresses may be represented symbolically.
This does not model native stack faults, asynchronous exceptions or general stack
memory. Maximum simultaneous internal calls is 32 (sentinel excluded), enforced
conservatively over all decoded paths using descending-offset dynamic programming:
RET depth0, CALL max(depth continuation,1+depth target), other ops max successor
depths. The graph contains at most1024 instructions; actual deterministic execution
including CALL/RET must terminate within1024 operations. Emitted Rust repeats
both resource checks. Returning to an earlier continuation is supported; backward
explicit branches/calls are rejected. Bounds are implementation acceptance limits.

Primary instruction provenance: Intel SDM volume2, order325383-081US Sept2023,
CALL and RET descriptions, https://cdrdv2-public.intel.com/789581/325383-sdm-vol-2abcd.pdf.
Near CALL saves the following EIP and transfers to the relative target; near RET
restores EIP from the stack. Neither changes arithmetic flags. Independently
implemented from that contract; no Wine source or runtime decoder is emitted.

Validation gates: helper result used by caller, nested/shared callees, flags
preserved across CALL/RET and changed by callee, unknown-state propagation;
independent literal instruction IR; negative/truncated/prefixed/far/indirect
encodings; target/continuation overlap and bounds; depth32/33 and dynamic1024/1025
boundaries. Existing mutation/decoder regressions and original Windows versus
native Linux fixture comparisons remain required. Windows Server2025 evidence
does not establish XP/7 or general application compatibility.

Measured local checks: 27 root test functions; 22 isolated functions (16 inherited
control tests plus 6 decoder/adapter comparison functions). 41 authored streams,
255 decoded records, 220,416 single-byte mutation calls and 131,072 two-byte/offset
comparisons pass. These counts include duplicates and shared semantics. Seven new
call fixtures execute generated ELF with expected exit and empty output; genuine
Windows results are an independent CI acceptance gate. Native stack fault and
asynchronous exception behavior remain outside the supported contract.

Post-core review adds an independent shared-callee conditional-return case: first
invocation returns1, second returns2, and caller adds3 for exit5. This exercises
distinct return sites under different invocation states. Unknown flags remain
unknown across CALL/RET; an untaken33-deep path is rejected by all-path policy.
No production change was required. The corpus now contains42 authored cases;
current final counts are recorded in Linear/PR CI evidence rather than inferred
from the earlier41-case checkpoint above.
