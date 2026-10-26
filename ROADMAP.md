# Roadmap

- M0: Rust workspace, strict PE parsing, CI, project governance, licensing.
- M1: one actual PE32 program translated to Rust, built to ELF, and compared with its Windows execution.
- M2: bounded carry/zero/sign/overflow flags, CMP and forward JC/JNC/JZ/JNZ/JL/JGE slice in draft review; wider instruction semantics remain open.
- M3: executable structure, imports and relocation semantics remain open.
- M4–M7: Windows compatibility runtime, dynamic observation, and desktop behavior.
- M8–M10: PE32+/x86-64, measured corpus expansion, optimization and reproducible releases.

No milestone is complete merely because generated Rust compiles. Each compatibility claim needs a versioned corpus, original execution baseline, and published comparison method.

## Next meaningful native program gate

The original M2 includes stack, memory and branching; M3 includes imports,
relocations and indirect calls. The current prototype has only a single EAX
state, four flags, forward conditions and entry return. The strict decoder is
in production, but this does not complete M2 or provide general function lifting.

Prioritize a bounded direct-call/return slice (SUB-506) over another immediate
arithmetic opcode. SUB EAX,imm32 would reuse comparison arithmetic but leave the
same structural barriers. A helper routine called from an authored entry point,
returning a value that the caller uses, advances a multi-function native program.
A restricted logical return-address stack can precede general stack memory only
while the accepted instructions cannot observe or modify stack addresses.

Next Astra High pass must specify and review that soundness boundary before
implementing exact forward E8 calls and C3 internal/entry returns. Require typed
IR, validated target/continuation boundaries, nonrecursive bounded call graphs,
nesting and execution caps, preserved EAX/flags and independent expected tests.
No PUSH/POP, ESP access, indirect calls, memory or APIs belong to this slice.
Original Windows execution must match generated ELF for helper, nested and shared
callee fixtures, in addition to existing regressions and deterministic source.
Then return to medium for verification. If the boundary cannot be enforced,
revise the scope before implementation rather than assuming stack semantics.

General stack/data memory is the next prerequisite for useful compiler output;
PE section mapping, relocation/import resolution and an independently implemented
small API contract are later prerequisites for an observable console application.
They should be separate evidence gates. XP/7 validation and a representative
application corpus remain unfulfilled; the current34 modern-Windows experiments
are prototype evidence only.
