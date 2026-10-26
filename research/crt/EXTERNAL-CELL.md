# SUB-545: owned external CRT state

`crt_external_cell` is a research Rust example. Its normal invocation binds the
unchanged PE but returns a blocked accessor result. `--isolated` explicitly supplies
a hypothetical isolated frame for the local zero-store effect. Neither path closes
accessor effects or grants production emission/startup eligibility.

## Binding and lifetime

The example reuses the reviewed sentinel image validator as a private module, then
checks the entire 0x1043..0x1058 caller window, zero-return helper0x16c0, thunk0x1d06,
HIGHLOW0x1d08 and named IAT0x20a8 import. Unexpected relocations through those forms
reject. Import descriptor/name/thunk walks have bounded counts and checked ranges.
The resulting Image owns its bytes; Session borrows that Image, so it cannot be
replaced while the session exists. No production module imports either example.

Each session owns a modeled cell and identity (process, CRT instance, generation).
Private capabilities borrow that exact session. Same-session capabilities alias;
two distinct sessions do not alias even if their IDs and synthetic VAs match.
A capability accepts no substitute object or numeric destination. Borrowing prevents
use after drop; explicit expiration and unknown external mutation revoke all existing
aliases. Revocation is sticky, with no reauthorization method. The synthetic
isolated constructor is a research premise, not a loader or real accessor result.

Regions require complete aligned nonwrapping four-byte backing, write permission,
and exclusion of the entire fixed image and an explicit nonempty protected stack
range. Stack location and mapping/ownership are hypothetical inputs, not facts
inferred from a successful run. Prior word bits may be unknown because the store
does not read them. A cell is Rust-owned Option<u32>; no VA is mapped, cast to a host
pointer or dereferenced. Integer parsing rejects negative, fractional and oversized
values; Rust identity fields use nonzero u64 values. Model identity alone does not
certify that two observations belong to the same real runtime generation.

The exact caller establishes ESI=0; a conforming accessor preserves it. The isolated
result represents EAX as an owned external pointer, leaves ECX/EDX/arithmetic flags
unknown and describes the four zero bytes. MOV itself preserves the post-accessor
flags, whose values remain unknown. The default unresolved accessor gives no EAX
pointer authority and blocks all stores. General memory, imported calls, arbitrary
pointer arithmetic, faults and CRT error/errno/exception effects are not implemented.
No runtime numeric ESP or return bytes are invented.

## Verification and accounting

`cargo test --locked --example crt_external_cell` runs seven new test functions
plus fourteen inherited sentinel functions from the reused module. The latter are
not new coverage or additional unique tests. New tests independently specify literal
zero bytes from0/64/FFFFFFFF/unknown, alias identity, foreign owner/generation,
expiration, sticky external mutation, readonly/misaligned/partial/protected ranges
and integer boundaries. State-only tests use an inert image marker; they do not
pretend to validate a PE. The separate cross-host harness exercises actual binding.

`check_external_cell.py EVIDENCE` builds the native example, checks default blocking,
four deterministic isolated vectors, four malformed integer inputs and thirty
independent single-byte changes across the new caller/helper/thunk windows. It
retains source hashes and the existing unchanged PE binding, then compares reports
with `--compare` on Linux. Compiler output is never edited; negative inputs are
separate temporary copies. All returned startup/emission certificates remain false.

The four existing /MD-/MT Windows process records support only the zero-input case
and observed repeated/thread pointer identity. Every recorded initial word was0;
nonzero and unknown transitions here are native Rust/model evidence, not new Windows
execution claims. No new CPU probe or translated ordinary CRT program is counted.
The previous twelve compiler comparisons,102 authored comparisons,18 launch checks
and four held-out rejections remain required. Four historical Windows fixture
termination timeouts remain unexplained; a repeat pass does not fix their cause.

Primary requirements and provenance are recorded in COMMODE-DESIGN.md: Microsoft's
__p__commode, global-state and fflush contracts, exact authored MSVC PE bytes and
independent probes. No Wine/Microsoft implementation source was imported; original
MIT OR Apache-2.0 applies. Windows Server2025 evidence is not XP/7 validation.

## Review and next closure gate

Review capability lifetime, object identity versus numeric identity, revocation,
protected range enforcement, exact image binding and independent source/probe hashes.
This implementation can express a local store under an explicit frame. The next
substantive gate is a defensible accessor effect summary: enumerate its required
external reads/writes, errno/TLS/exception and nonreturn behavior, lifetime and
concurrency restrictions, and determine whether the primary contract supports a
bounded success domain. If effects cannot be closed, retain a named blocker rather
than compose a fabricated successful startup. Earlier startup imports and later
exit registration still require separate closure. Further local-model tests alone
cannot establish ordinary CRT equivalence.
