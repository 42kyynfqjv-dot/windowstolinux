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

## Focused review and bounded timeout diagnosis

Review found no production cleanup defect: exact byte guard, shared two-word
validation before truncation, pointer Data disposal, protected-word rejection,
flags None until CMP, and frozen shared-program provenance remain consistent.
Existing54 root functions and10 native/52 rejection cases are retained.

At least two distinct original-Windows waits are documented. Historical run
40269378607 failed job121398673975 after corpus13, waiting15 seconds for corpus14;
explicit retry job121398912221 passed. The connector lists only latest-attempt
jobs, so that view alone conceals the original failure; direct old job logs and
SUB515-LINKER-DESIGN.md preserve it. Recent run40279659683 job121429919088 timed
out in imported max after hello/changed/one. These are different PE fixtures.
Both fail in Python waiting for an original child, before conversion. Available
logs do not distinguish loader/CRT/program execution from runner scheduling.
Recent final run40279827103 is a separate changed-commit run, not an automatic
in-test retry. Neither successful follow-up establishes a resolved cause.

The new original-only Windows probe preregisters18 mandatory launches: max,
corpus14 and Hello control, three repetitions each under reused and fresh paths.
It records PE hash, PID, spawn duration, total duration, full stdout/stderr, exit
and timeout, persists incremental JSON and failed authored PE bytes as artifacts.
Every sample must pass; a failed sample fails the job even if later samples pass.
The15-second wait and explicit failure remain unchanged. No converter, security
setting changes, retry-until-green or compatibility expansion is involved. Byte
construction for imported fixtures moves unchanged into an importable module;
normal Windows/Linux comparisons still run separately with the same assertions.

A non-reproduction narrows no root cause by itself. If a timeout reproduces, use
its exact artifact/hash and timing to define a bounded process/loader investigation
before more features. Medium suffices for this harness work; unsupported ABI/tail
transfer design still needs a separate Astra High decision.
