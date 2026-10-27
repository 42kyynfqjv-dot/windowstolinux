# Original record binding: concrete integration blocker and correction

At checkpoint 26b8d9d, workflow 40588769618 downloaded the same retained rcedit
artifact (PE SHA256 ce252fb1eddd05c3ea6acd73871995b1badd32446d76c6df07abaf8fa44fd22f).
The new reader requires unique complete file backing, verifies displayed instruction
bytes against the PE, and never grants execution authority. Its bounded ranges
may include adjacent functions; they are not a complete CFG.

## New measured facts

Scope header at 0x5191f8: `feffffff00000000ccffffff00000000`, signed words
`[-2, 0, -52, 0]`. The third word matches the independently derived saved-cookie
slot EBP-52. Interpreting every header field still requires the guard-check helper.

Cookie initialization at 0x475c79 writes the cookie at 0x51c140 and its complement
at **0x51c180**, not cookie+4. The isolated component's adjacent-pair constructor
could not represent these unchanged instructions. It now takes separate addresses
and maps separate four-byte words with rollback if either mapping fails. A new
literal regression checks the 64-byte separation, unmapped gap, failed fourth-map
rollback and complement corruption. No application address is embedded in the
component; the fixed addresses here belong solely to artifact measurement.

## Why exception integration is still blocked

The actual handler at 0x47b290 is executable code with observable effects:

- At 0x47b2a9 it calls the SSE2 floating-point exception filter, then at 0x47b2ae
  writes EAX back into the exception record's code word.
- It decodes the scope pointer with the module cookie, calls guard helper
  0x47b250, and calls `__except_validate_context_record` before inspecting flags.
- It tests exception flags against 0x66, traverses scope entries, calls filters,
  branches on negative/zero/positive filter returns and invokes local unwind.
- The positive path at 0x47b36a checks C++ exception code 0xe06d7363 and reaches
  an exception-object destructor pointer validation path. Its full successors
  are outside this 256-byte excerpt.

Thus a list of handler addresses and a continuable Boolean cannot implement this
handler. Nor can the component's permanent process-wide pending barrier execute
its writes. That barrier remains correct for the current rejection-only boundary;
removing it would invent exception semantics.

## Cohesive next implementation contract

Use a dispatcher execution state distinct from ordinary continuation, with explicit
owned exception-record and CONTEXT mappings and controlled handler memory effects.
Mechanically lift the original prolog, guard helper, handler and reachable helpers
through shared IR. Bind scope-selected cookie slots and preserve all original
register/stack/flag effects. Resume ordinary execution only after validated filter
result, continuability, unwind/termination and context restoration transitions.
Unknown helper, destructor or external effects must keep admission blocked.

Before implementing that transition, retrieve complete original ranges for
0x47b250, the filter/context-validation/local-unwind thunks and their targets, and
the positive handler path. Establish the original incoming FS chain with a separately
labeled original-entry observation; do not infer an empty chain from authored probes.
This is a specific dependency/effect closure experiment, not another generic state
model. Original code execution and adverse-path Windows/ELF comparisons are required
before claiming new translation; none are added at this checkpoint.

The reviewed eb63438 PR CI 40586550735 and push CI 40586540913 both completed
successfully. Previous original-Windows timeouts remain unexplained. Current
checkpoint CI and results are recorded in PR45/SUB-579; keep both work and review
in that existing PR, draft and In Progress.
