# Relational loop proof: architecture decision required before emission

The next integration step needs an expressive relational verifier. This is a
correctness-critical compiler architecture choice, not another opcode addition.
No production admission change accompanies this experiment.

## Reproduced limitation

The O1/O2 transform loops need `index < current_read_length`; the write loop needs
`sent + written <= count` and `written > 0`. Independent intervals lose these
relations at joins. Even after `count > 0`, ranges `count in [1,256]` and
`index in [0,256]` admit an invalid access. A length from an earlier read cannot
justify an access after a newer read returns zero, even at the same buffer address.
Unsigned wraparound must be ruled out for the actual 32-bit additions/subtractions.

The standalone experiment expresses universal implications, including bitvector
write progress and read-epoch constraints. Negated valid obligations are UNSAT;
weakened bounds and stale epochs produce SAT counterexamples. Forced resource
exhaustion returns UNKNOWN and is rejected. These nine checks validate the
proposed proof language and failure policy. They do not prove either PE, generate
invariants, validate x86 lowering, or implement typed frame ownership/emission.

## Alternatives and recommendation

| Approach | Consequence |
|---|---|
| Custom affine relational domain and fixed point | No external solver, but new widening, substitution, correlation and bitvector soundness code must be implemented and independently validated. Existing per-value intervals cannot simply be reused. |
| Compiler-time SMT obligations with Z3 | Mature exact integer/bitvector reasoning; adds a pinned local compiler dependency and requires sound CFG/SSA/epoch encoding, induction and explicit resource failure handling. No generated-runtime solver dependency. |
| Runtime checks without static proof | Does not meet the current admission contract. Reject as an implementation shortcut. |

Recommend a compiler-time SMT verifier behind the existing emission barrier.
This replaces planned custom arithmetic proof machinery, not the native runtime
or the decoder. No production dependency has been added yet. The research CI
uses a pinned, SHA-256 verified Linux x86_64 wheel in an isolated virtualenv.
Z3 4.15.4's upstream license is MIT; provenance.json records the exact package,
wheel hash and tagged license source. No third-party implementation is copied or
redistributed here. If a later distribution bundles Z3, include its applicable
notices. Production Windows/Linux solver provisioning remains an integration gate.

## One cohesive implementation route in PR25

1. Preserve the checked graph and import bindings as private proof inputs. Run a
   typed frame-shape fixed point over architectural register indices, protected
   saved/return words, local byte regions and stdcall argument cleanup. Reject
   inconsistent layouts and unresolved pointer/handle/function provenance.
2. Compute dominators and loop cutpoints generically. Initially reject irreducible
   control flow. Split into acyclic regions and produce SSA snapshots for each
   edge, including partial-register masks and x86 flags. Avoid host-address
   assumptions for ESP arithmetic.
3. Introduce fresh read epochs, result classes and count values at each ReadFile.
   Havoc the requested buffer's initialization and contents before adding the
   conditional successful-prefix fact. Invalidate old dependent snapshots and
   aliases. GetLastError must refer to the immediate failed call's state.
4. Generate invariant candidates from typed memory/API bounds and decoded guard
   expressions, independent of artifact names, hashes, outputs or observed inputs.
   Prove base and inductive-step obligations for every incoming edge; discard
   noninductive candidates. No bounded unrolling masquerading as loop proof.
5. Check every memory range, initialized read, call argument, protected slot,
   arithmetic/flag use, cleanup and portable exit under those invariants. Require
   UNSAT for each negated obligation. SAT, UNKNOWN, solver absence/version mismatch,
   malformed response, timeout and resource exhaustion all block emission. Bound
   compiler expression size, candidates and solver work; never impose a hidden
   total-input limit on the emitted stream loop.
6. A private proof result binds the exact normalized graph, API contracts and
   runtime support version. Emit iterative Rust blocks from that same graph,
   with raw owned file/pipe descriptor adapters. No runtime instruction decoder,
   solver, source-algorithm template or AI dependency. Runtime checks may provide
   defense in depth but cannot compensate for unproved admission obligations.
7. Require unchanged O1/O2 PE->Rust->ELF comparisons, deterministic Rust across
   hosts, full file/pipe/error evidence and independent frame/register/guard
   permutations plus stale-epoch, alias, overflow and unknown-state negatives.

The decision is whether to adopt the local compiler-time solver dependency or
fund the larger custom relational-domain implementation. The recommended solver
route has no paid service, credentials, network-at-conversion or generated-runtime
requirement. It still requires implementation and substantive soundness review;
these standalone results do not close the CLI milestone.

Reproduce on Linux x86_64:

```
python3 -m venv /tmp/w2l-proof-env
/tmp/w2l-proof-env/bin/pip install --require-hashes --no-deps -r research/cli/v2/proof/requirements.txt
/tmp/w2l-proof-env/bin/python research/cli/v2/proof/obligations.py
```

Primary references: https://github.com/Z3Prover/z3/tree/z3-4.15.4,
https://microsoft.github.io/z3guide/docs/theories/Bitvectors/,
https://smt-lib.org/logics-all.shtml (QF_BV). Counterexample models are not
canonical; compare required SAT/UNSAT/UNKNOWN outcomes, not incidental assignments.
