# SUB-557 production integration

Production scalar values now retain affine leaves or immutable reference-counted
Add/Mul nodes. Each node caches expanded occurrence count and depth. Construction
checks the proposed count <=63 and depth <=12 before allocation; child clones copy
references. Range traversal follows at most63 occurrences. Endpoint calculations
use u64: maximum u32 product fits, and maximum sum needs only33 bits. A modular
bucket crossing yields the full u32 range. Aliases retain immutable snapshots;
correlations may lose precision but cannot narrow away a real result.

The exact seven inventoried forms normalize to shared scalar operations. Existing
affine operations retain their implementation; copying accepts either scalar kind.
Nonlinear immediate arithmetic creates a bounded Add node. Nonlinear predicates,
LEA operands and low16 projections reject. Typed pointers and unknown registers
cannot become scalar operands. ADD/IMUL invalidate abstract flags. Native ADD/IMUL
emit wrapping operations; flags are unobservable until a supported CMP/TEST resets
them. No undefined flag is asserted known. Complete path-specific API classes,
initialized-byte bounds, saved slots, metadata/relocation binding and exit proof
remain mandatory. There is no runtime expression evaluator or decoder dependency.

90 root functions include two new functions: exact squares IR and unsafe proof
paths with100 native digit-pair expectations, and independent modular boundary/
resource tests. The inherited six scalar register permutations still exercise
shared proof/emission. The new code uses both ECX and EDX IMUL and register ADD;
unlisted byte forms remain rejected. Eight nonlinear Python model functions and
eight affine functions are inherited evidence, not new production test counts.

The unchanged frozen C, compiler flags and 51 Windows expectations remain fixed.
CI now requires guard_join and squares acceptance, identical source across hosts
and converter environments,17 Windows/ELF comparisons each,105 additional native
inputs and9 separate unsafe image rejections each. Helper remains rejected. The
squares expected digit result uses independent decimal arithmetic. Mutations are
written to separate files and cannot alter the baseline PE. Inventory checker
verifies seven literal forms and same-PE provenance; execution is checked by the
separate comparison harness. Prior14 compiler programs remain required; squares
is one additional program only after the end-to-end gate passes.

Next medium review: audit shared-node accounting, operand capture and clone
behavior, signed IMUL low32 correspondence, conservative flag rejection, affine
versus nonlinear predicate separation, range/ownership proof and actual artifact
hashes/output. Interval imprecision can reject safe programs. Nonlinear guards,
helper-pointer calls, ordinary CRT and broader memory/loop forms remain outside
scope. Procfs/stable environment, encoding/resource, valid-stack/no-fault and
unobserved actual-load-base premises persist. Four historical Windows timeout
causes remain unexplained. Modern Windows evidence is not XP/7 validation.
