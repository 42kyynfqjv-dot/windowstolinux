# SUB-562 integrated composition: first implementation checkpoint

The complete frozen eight-artifact listings were inventoried before implementation
in full-inventory.json, using the unchanged PEs from final SUB-561 CI40414130330.
Each entry records its PE hash, true entry, all instruction/padding bytes and
assembly. This historical inventory is evidence, never converter admission policy.
Frozen source/flags/vectors are untouched.

The shared input IR/proof/emitter now supports the seven reviewed post-call forms,
explicit no-base scalar LEA and affine predicate entailment before exact refinement.
The enclosure uses comparison-width modular projection; crossing intervals become
unknown. Constant/multi-symbol proven branches preserve path facts; unresolved
multivariate predicates reject. Existing register clobber, buffer and protected
return rules remain. No fixture hash or whole-body recognizer grants acceptance.

Current acceptance target: composed O2, 14 original/ELF cases. The other seven
remain rejected. This checkpoint does NOT complete the 8-artifact/112-pair milestone.
Two new Rust test functions cover native composition/unsafe paths and independent
width/wrap/constant/multivariate predicate boundaries; nine native input cases run
inside the composition function. Model tests are inherited, not additional counts.

Complete inventory exposes coupled remaining architecture requirements:

* O1 prologues save EBP, set EBP=ESP, allocate with PUSH ECX or SUB, and restore
  through LEAVE. Unknown pushed ECX must allocate unknown bytes, never initialize
  them. EBP-relative slots need frame identity, not an invented absolute address.
* Shared O2 preserves scalar results in ESI and adjusts buffer addresses around
  saved slots; shared O1 keeps EDX through a helper whose actual body preserves it.
* Nested O1 saves both ESI and EDI, uses one-argument calls and CMOVBE/CMOVE.
  Nested O2 has a backward-address JE to a shared error epilogue, without a cycle.
  Both retain EDX across a decoded callee. Blanket ABI clobber loses a required
  fact; safe integration needs actual internal-call effect propagation. Unknown
  external calls must retain their conservative clobber contract.
* Larger O1/O2 need capacity5/12-byte allocation, four UTF16 input symbols plus
  length, WORD reads at offsets0/2/4/6 and JB refinement. Current fixed acquisition
  projection and three-symbol expressions cannot represent that domain.
* Additional arithmetic includes immediate IMUL and register CMP/ADD. Their flag
  effects and source-before-write behavior must compose with CMOV and joins.

Next work stays in this same milestone/PR: shared typed frame/owner+offset state,
capacity-aware acquisition projection and input symbols, actual decoded internal
return effects, and graph-based cycle detection independent of address order.
These need a coupled contract/implementation with independent protected-slot,
alias/unknown-byte, CMOV, backward-acyclic/cyclic and capacity-boundary tests.
Do not admit new forms merely to reach another first error. The old rejection
barriers stand until complete state/emission correspondence is established.
No new resource or user permission is needed. Broad I/O and the later useful CLI
remain separate. Procfs/stable-environment/no-fault/load-base/XP7 assumptions and
four historical unexplained timeouts remain.
