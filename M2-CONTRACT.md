# Bounded M2 contract (SUB-501)

The existing restricted PE console profile remains the input contract. The review additionally rejects sections overlapping the virtual header range. This is a source-level validation defect with a regression fixture; no claim of Windows execution for that malformed fixture is made.

The production lifter supports MOV EAX,imm32; ADD EAX,imm32; XOR EAX,EAX; RET; and forward short JC/JNC/JZ/JNZ. ADD sets CF from unsigned carry and ZF from the 32-bit result; XOR clears CF and sets ZF; MOV preserves both. Other flags have no supported readers and are not modeled. Instruction semantics follow the x86 ADD, XOR, MOV and Jcc contracts (Intel SDM instruction reference); no external implementation source is used.

Both conditional successors are decoded, even when constant entry-state analysis proves one untaken. Unsupported instructions, overlapping instruction boundaries, targets outside executable bytes, negative displacements, unknown entry flags/EAX on the evaluated path, and exit values above 255 are rejected. Zero displacement is allowed: both successors are the following instruction. All successors advance, so the graph is acyclic. Decoding and generated execution are capped at 1024 instructions.

The emitted Rust contains fixed instruction arms and successors. It executes translated operations and conditionals; it does not decode or execute original bytes at runtime. Since supported inputs have no external reads, the path is deterministic. A pre-emission evaluator verifies initialization, termination and the exit domain. Generated Options retain initialization assertions. No memory, APIs, backward control flow, signed conditions, parity or overflow-flag conditions are supported.

The Windows/Linux matrix includes the five M1 cases and ten branch cases: taken and untaken for each condition, MOV preserving ZF, and XOR clearing CF. Modern Windows Server 2025 results do not establish XP/7 compatibility. The older straight-line implementation has been removed. Its useful input, arithmetic, exit-range and executable-boundary regressions now exercise the production decoder and validator.
