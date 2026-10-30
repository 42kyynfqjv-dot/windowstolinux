# Original initializer table, callback ownership and ordered rollback

Historical checkpoint at `d193e00`. The subsequent [page-permission integration](VIRTUAL-PROTECT.md) executes the third callback; the original evidence below is retained.

## Connected original execution

The explicit native profile now executes the original initializer continuation
40195f, wrapper407653 and full table loop40c926..40c98d over the unchanged16 pairs
at415fb8..416038. The first callback407558 writes41c178 into41d134 through original
MOV/RET instructions. The second callback407587 reads the live cookie41c000 and
executes all five original scalar-store callees. Eight destination words retain
that runtime cookie; no observed answer is substituted.

The third callback408113 executes its original frame and arguments, then rejects
at CALL408129/IAT4150b0, imported kernel32.VirtualProtect. The actual inputs are
address41e000, size128, PAGE_READONLY2 and the owned four-byte stack output at
EBP-4. The API has not run and its output/protection effects are not certified.
Prior FLS publication, lock/count, first callback and cookie-dependent stores
remain live at rejection. No rollback is invented for this unsupported call.
Default admission, full startup/rcedit and Windows resource-failure equivalence
remain unresolved. This is original instruction component execution, not a new
whole-PE Windows/ELF comparison.

## Shared loop and ownership contract

The core lowers the actual decoded loop, branches, guard/indirect calls and RET;
it does not replace the loop with a hard-coded list of successful effects. Its
bounded input is an owned, immutable, aligned table of up to16 eight-byte pairs
within one canonical process-image section. Bounds must be fully known scalar
arguments, as the original wrapper supplies; pointer values are not silently
converted to fresh table authority. Full original loop bytes, table
contents and image lifetime are revalidated at calls/return. The production
binding also checks the exact original table bytes. Independent authored tables
exercise the same core without that original-table predicate.

A local guard receipt binds the actual table index, initialization/cleanup phase
and executable target owner. ECX and EBX must identify the selected word. The
actual original RET0 guard stub executes, then its receipt is consumed once at
the matching indirect CALL. The caller's protected return and saved registers are
validated by shared call machinery. A callback is completed only after its actual
protected return and AL decision. Unknown AL cannot prove a branch or completion.
Executable-address ownership alone is not a callback-body proof: production
execution selects only byte-bound emitted bodies and rejects all unproved effects.

The loop records completed non-null initializers. A failed AL0 initializer does
not count as completed. Cleanup follows the original reverse traversal, skips
ineligible/null entries and can consume a completed entry once. Return is checked
against completion/cleanup state. Throwing/rejected callbacks and failed cleanup
retain their prior writes without issuing completion or restoration authority.
This is distinct from a supported guest initializer returning false, which runs
the original rollback arm. All mapped pointer bounds remain checked, including
transient loop arithmetic; table layouts outside that proof domain may reject.

Initializer401945 now includes its original complete branch/RET tail. Its existing
failure-cleanup CALL4024e9 remains explicitly unbound where reached. No fragment
fallthrough or external callback becomes a successful original return.

## Independent tests and evidence boundaries

Eighteen authored table/callback-contract cases execute the original loop. They
cover success, failures at entries0/1/3, full16-entry late failure, duplicate targets,
empty tables, null initializer/cleanup fields, reverse cleanup order, cleanup
failure after earlier writes, stale table/code ownership, changed guard/loop bytes,
misalignment/excess extent, stale typed bounds at reused addresses, missing
protected RET and saved-register corruption.
Every expected success explicitly asserts success, AL, saved registers and complete
ordered events. Failures preserve observable writes and reject completion.

These callbacks supply authored boundary outcomes solely to test the loop's
protocol; they are not translations or Windows observations of the original16
callback bodies. Production entry executes two actual original callback bodies and
stops in the third. Separate negative mutations of the original table, loop, first
helper and a later scalar-store helper reject. The later-helper mutation proves
that the first callback and the first cookie store remain while later stores do
not occur. No source/compiler flags or frozen PE was changed to obtain acceptance;
mutant copies are separate rejection fixtures and carry no Windows comparison claim.

Review of4bc05bb retained the native-slot marker, opaque scalar values without
pointer/PTD authority, and protected-argument checks before failure effects. No new
FLS authority defect was found. All predecessor workflows41072504174,
41072489824 and41072489854 passed. Historical original-Windows process timeout
causes remain unresolved. The retained1MiB native stack regression remains required.

Initial local table tests exposed an incorrect test entry ABI (the shared fixture
defaulted to cleanup12 instead of cdecl0); that fixture was corrected. Clippy also
caught a test-only hex-helper dependency and style issues; the source decoder now
uses a local static-literal parser and the all-target gate is retained. Failed logs
are preserved. [Machine-readable evidence](evidence/initializer-table.json) records
source/test/artifact hashes and the five retained recorded wrapper comparisons.
No fresh original-Windows initializer observations or whole-PE pairs are claimed.

## Next cohesive architecture gate

VirtualProtect is the exact next original API boundary. Its
[primary contract](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
changes every page intersecting the requested range, reports the first page's old
protection and fails without changing any protections if any requested page is
uncommitted. Its old-protection output must be valid. This is not permission to
replace one allocation owner with another or to copy/retag image data.

Current guest_memory Region has one Permissions value for the whole allocation;
validate_writable/executable inspect that value. Protecting only page41e000 must
preserve the data mapping/capability and unrelated writable pages. A bounded
Astra High pass is justified for page-granular permission state integrated with
all checked accesses, old-protection output ordering, lifetime/proof invalidation,
page/reservation bounds and failure atomicity. Keep unsupported flags, executable
transitions, guard pages and unproved Windows errors rejected. Do not modify host
security settings or assume a passing Windows sample proves arbitrary failure
behavior. Independent alias/boundary/output/error tests plus original Windows/native
conformance are required before admitting this API.

Review also tightened the new bound adapter: a retired pointer may legitimately
be transported as opaque data, but numeric extraction must not replace its old
identity with a new image mapping at the same address. Tests allocate/retire an
input region, map the PE at its reused address, and pass the retired begin or end
pointer. Both reject with no callback effects. Two independently compiled mutants
restore the permissive conversion for one bound at a time; each falsely accepts
its stale case and triggers the regression. Fabricated foreign owners were already
rejected by the lower memory layer; the retained regression uses actually issued
retired capabilities rather than bypassing that validation.

Validation:283 CRT tests passed, both artifact tests passed in reviewed replay,75
Python tests passed (one existing skip), and Clippy/format passed. New-head CI is
a separate gate; predecessor checks do not validate this commit.
