# SUB-522 exact two-word cleanup

The linker profile admits only83 C4 08 ADD ESP,8, using a private CleanupTwo Op.
It shares the existing checked cleanup transition: validate exactly two complete
current-owner Data words, then truncate atomically. Saved ESI, Entry, Return,
foreign-owner or missing words reject. Pointer Data can be discarded but never
converted to scalar. All tracked flags become unknown because absolute ESP is
unknown; MOV does not repair them, CMP can. No numeric ESP or fabricated flags.
Other profiles/forms, limits, call contexts, pointer provenance and balanced
terminal checks remain unchanged. Intel ADD instruction provenance and the ABI
assumptions are inherited from SUB520-THIRD-ARGUMENT.md.

One new production-state test checks every protected tag at both positions,
atomic word preservation on rejection, pointer Data cleanup, adjacent ESI save,
unknown flags/MOV/CMP and unfinished terminal cleanup. CLI/native coverage now has
ten deterministic literal cases and52 rejections (21 existing slots,26 new cases,
five executable truncations). The new shared program checks both12 and7 after
five- and two-word cleanup. Negatives include a protected return on an untaken
branch, saved ESI crossing, unknown flags and a leftover Data word. These are
native-only literal cases, separate from real compiler comparisons.

The frozen compiler/structures/shared.c source and original MSVC flags remain
unchanged. Both CI host harnesses now require shared acceptance plus unchanged
nested/conditional rejection. The shared hashed PE must independently convert
on Windows/Linux to identical Rust and native Shared/empty stderr/exit0. Five
prior compiled programs and102 authored Windows/Linux pairs remain mandatory.
No source or PE patching, flag search, general stack support or broader API scope.
Successful CI is required before claiming this new compiler comparison passed.

Next focused review: exact form restrictions, owner/protected-word validation,
unknown flag consumption, all-path shared contexts and frozen artifact provenance.
Medium effort is sufficient; a new architecture uncertainty requires a concrete
Astra High handoff. Ordinary CRT/XP7/general apps and arbitrary stack fault behavior
remain unsupported/unverified. Existing valid-stack/no-fault/regular-file output
assumptions and historical unexplained corpus timeout remain explicit.

## CI timeout evidence

Initial CI40279659683 failed in the original Windows imported-output max case:
hello/changed/one passed, then the original fixture exceeded15 seconds. This
script never invokes the converter in Windows mode. Cause remains unexplained;
the failure is retained. Launch identity/PE hash and timeout stdout/stderr are
now logged, with the same15-second bound and no automatic retries or acceptance
relaxation. A subsequent pass would not establish that the cause is resolved.
