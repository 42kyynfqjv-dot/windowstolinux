# Original onexit routing and registered allocation prefix

Historical checkpoint at `b936882`. Current execution and limitations are in
[Original onexit fill and first publication](ONEXIT-FILL.md).

## Actual connected result

The unchanged authored entry now executes CALL `0x401596 -> 0x401b0f`, the real
wrapper `0x401ae1`, its sentinel branch through `0x4074a8`, and the table wrapper
`0x407525`. The sentinel at `0x41cc88` selects **table `0x41ce88`**, not the
separate `0x41cc88` table. Original locals contain distinct acquisition/release
references holding logical lock 2 and a pair referencing table/callback argument
slots. The manager `0x407260` installs a live EH4 record using original helper
`0x401e60`, size12, scope `0x41b500`, then acquires the actual indexed lock.

The original append prefix at `0x4072bb` reads the three cookie-encoded empty
table words, executes XOR/ROR and the original growth arithmetic (32 entries,
128 bytes). CALL `0x407321 -> 0x40c850` runs the original checked recalloc and
NULL-realloc path through `0x410ca0 -> 0x408730`. The existing canonical process
heap producer performs actual flags0 allocation; the new bytes remain unknown.

Execution rejects **before CALL `0x40c8ae -> 0x402370` (original memset)**, with
actual destination/zero/128 arguments on the stack. The 128-byte allocation is
live and uninitialized; the inner registered frame, logical lock2, original
callback argument, scope0/state1 and earlier x87/initializer effects remain.
The encoded table is unchanged. **No callback has been published, and no native
registration completion is claimed.** No cleanup, memset, resize or failed-API
return is replaced by assumed success. This remains explicit-profile original
component execution, not full startup/formatter/rcedit/default admission.

## Ownership and routing contracts

`CrtOnexitInput` borrows the actual callback argument and unique protected return
for this activation. It validates initialized scalar callback bits against a
live immutable executable view in the same image and snapshots the live cookie.
Unknown/null/typed or non-executable callbacks are outside this supported domain.
The witness grants no successful registration, callable-body or continuation
receipt. Original argument words retain their original values and identities.
Changed arguments, cookie, target lifetime, duplicate return tags or expired
process/thread/initialization reject before further effects. Reusing a completed
or suspended activation cannot issue another registration request.

The registered manager reuses shared prolog/epilog, canonical frame and logical
lock APIs. Its immutable original scope bytes are checked. **Logical IDs and
owned slots are distinct**: actual startup's logical lock2 maps to owned slot3;
validation follows the real storage address, not a guessed slot number. The
normal original cleanup at `0x4072af` and RET12 are independently exercised with
an explicitly declared append-body cut. Exceptional cleanup/dispatch and exit
table draining remain unsupported.

Table words may contain scalar encoded bits, never implicit pointer authority.
The currently supported append prefix requires the semantic empty encoding:
all three words equal the current cookie, decoding to null without granting a
pointer. Nonempty words reject. A negative case allocates a real live buffer and
stores numerically correct encodings of its base/end/limit: it **still rejects**
without a producer-bound association. Looking up a plausible live address is not
sufficient provenance. Other non-null size/reallocation/free, errno/new-handler
and publication paths remain explicit rejections.

## Conditional memory reads

This path required reusable 32-bit CMOVE/CMOVA memory operands using the existing
conditional-selection IR/emitter. The source memory is read **before** evaluating
the condition, including when the condition is false or unknown. No observation
or possible fault is erased by pruning an untaken selector. Destination and
flags are preserved on failure; all integer flags remain unchanged by selection.
Other widths remain rejected. A 36-case native matrix covers equal/not-equal/
above selectors, all CF/ZF combinations, and expired source storage even with
false/unknown conditions.

## Independent tests and provenance

[Expectations](evidence/onexit-expectations.json) were frozen before implementation.
[Results and reproduction hashes](evidence/onexit-registration.json) separate:

* 24 routing cases, including three repeated requests in one case. They use an
  explicit manager-result cut to check actual argument routing, callback order,
  null/unknown/alias/stale inputs, exact 0/-1 wrapper results, mutated code,
  partial writes and replay. They do not represent registered callbacks.
* 17 registered-manager cases. Declared append cuts exercise real lock/scope,
  cleanup/RET12, corrupt guards, wrong saved state and prior effects. Actual body
  cases execute through native allocation/memset rejection or fail closed on
  resource/heap/encoded-word faults. Reentry cannot duplicate the allocation.
* The existing original-entry case executes this connected path from the same
  PE under the established explicit native/CPU/entropy/x87 profiles. It now
  retains four heap allocations on Linux (including the new128-byte buffer).
* Five retained recorded Windows wrapper component comparisons; **zero new
  whole-PE Windows/ELF pairs**, and zero completed native registrations.

Predecessor `dcf7882`: both the push Rust and startup-inventory workflows passed.
PR Rust run `41307421773` failed on original Windows corpus case5, job
`124850559514`. Artifact `13084081086` preserves matching C05 output while the
creation-time-verified original process remained alive after15 seconds. The PE
is byte-identical to `generate.build(5)`. That Windows path does not execute the
converter; WCT is not a PC/stack trace or a diagnosis. The cause is unresolved,
independently of x87/registration semantics. No timeout was raised and no retry
was used to mask this failure. Earlier case19/hello/other timeouts remain intact.

## Cohesive next integration gate

Complete the actual original memset paths with checked range, permissions,
initialization, direction/count and partial-failure behavior; do not substitute
zeroed allocation for the original stores. Then execute original scalar encoding
helper `0x406d62`, the cookie-fill/store/publication body and normal cleanup.
Bind encoded fields to actual producer/cookie/write events and the same live
allocation/callback identities. Ordinary writes, cookie changes, freeing and
resizing must revoke stale associations. Implement non-null resize only with
explicit alias/lifetime and failure/resource contracts. Verify repeated append
and publication order from original instructions before claiming registration.

Sol can independently review the current diff and evidence. The demonstrated
live-address/encoded-authority gap justifies a bounded Astra High design pass for
this connected ownership/publication/resize scope if needed. This is a concrete
memory/proof integration problem, not a missing kernel/driver dependency.
All broader startup, callback execution/draining, incoming/exceptional delivery,
collided unwind, non-null free, error/new-handler, native close/EOF and broader
resource/encoding/XP7 equivalence limits remain unproved. No Ultra, merge or
release is part of this milestone.
