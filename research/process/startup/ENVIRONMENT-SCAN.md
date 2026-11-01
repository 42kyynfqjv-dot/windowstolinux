# Original UTF16 environment scan

The controlled-launch path executes the unchanged helper at **0x40b92f** from
CALL0x40b980. Its original loads, comparisons, loops, pointer arithmetic and
protected return lower through the shared checked instruction emitter. The
caller executes pointer subtraction, arithmetic shift by one (bytes to UTF16
units), argument pushes and its count store. It stops **before conversion query
CALL0x40b996 →0x40b8c5**. No narrow environment table or original free is claimed.

The GetEnvironmentStringsW producer still returns a distinct immutable snapshot
from the explicit `w2l-controlled-environment-v1` declaration. No real host
variables are acquired or logged. Snapshot capability, process identity, bounds
and lifetime remain authoritative for every original load and pointer operation.
The scanner does not decode Unicode or create authority from numeric addresses.
Surrogate pairs and lone surrogate words are scanned as words; whether subsequent
conversion accepts them is a separate contract.

## Termination and failure effects

For a nonempty block, the helper scans each NUL-terminated entry and the final
NUL, returning one past that word. The caller's difference/shift includes both
terminators. The empty fast path reads only the first NUL word and returns two
bytes past the root, yielding count **one**, although the acquired empty block
contains two words. A standalone one-NUL buffer exercises that actual fast path;
it is not admitted as a valid acquired environment. No extra read or fabricated
validation is inserted into the original instruction path.

Missing terminators and unknown or retired storage reject at the original read
or decision. Already executed stack/register effects remain. No success return
or cleanup is synthesized. The owned producer guarantees the complete double-NUL
layout; arbitrary malformed test buffers do not gain producer authority.
The 262144-step scanner budget covers the declared maximum32767 words and256
entries (five loop instructions per word plus bounded entry/frame work).
This is an instruction execution bound, not a relaxed timeout or proof bypass.

[Region hashes and evidence](evidence/environment-scan.json).

## Review and acceptance checks

Twelve independent native cases cover empty and one-NUL fast paths, Unicode and
lone surrogate words, multiple entries, missing terminators, unknown bytes,
stale storage, numeric addresses lacking capability authority, saved-register
restoration, replay and the maximum declared word count under512KiB. Ten
unchanged-artifact cases include original acquisition, empty/Unicode input,
mutated prolog/import/scanner bytes and lifecycle/owner/return failures. A scanner
mutation rejects after acquisition and preserves that earlier live snapshot.
The full controlled original-entry check must reach0x40b996 and retain prior
startup state. This is component execution with a deliberately selected launch
profile, not whole unchanged-binary entry-to-exit proof or default admission.

The predecessor ef59eb6 replay completed at emitted Rust SHA256
`bdd8aaecb9abbd390e579bc15cc033f87f66d359e0aca683957a4a55045c9038`, matching its
recorded canonical hash: five retained Windows component comparisons and zero
whole-PE translation pairs. The earlier50d4f66 local run contains later source
and is not pinned-head evidence. Its Windows `changed` launch timeout is separate
and unresolved; retained failure artifacts are not replaced by later passes.

`check_normal_wrapper.py` now records an initial source manifest and checks the
same source hashes and Git identity before writing a final report. Only a clean
relevant source tree can name a pinned commit. Changed source/HEAD rejects the
report and retains partial evidence. Synthetic tests cover changed/added Rust
and JSON, a changed commit, dirty-source qualification and retained failures.
This checks run-boundary source identity; no concurrent source editing is an
accepted replay workflow.

Next compose the existing original conversion wrapper, then prove allocation,
copy, matching free, publication and failure ordering before environment-table
admission. Full propagation, API failure equivalence, startup/rcedit/default
support and historical Windows timeout causes remain unresolved.

The direct artifact fixture supplies unknown scalar ECX for the original scratch
pushes. Its previous opaque saved-register token correctly rejected the later
count overwrite; runtime protection is retained. Connected entry independently
checks the new ECX result from the last scanned Unicode entry, rather than
expecting the API's earlier unknown ECX to remain unchanged.

Local final validation:349 CRT passes, two artifact gates separately handled;
canonical controlled entry and ten artifact cases pass;112 Python tests with
one skip;Clippy all targets warnings denied and formatting pass. All152 word
cases pass with the unchanged512KiB limit and64KiB environment padding. Pushed
head replay and full CI remain separate gates; no pending run is called a pass.

Final report review found a stale `fp_explicit_profile_boundary` annotation
naming0x40b980 after actual execution advanced. It now names0x40b996. The aa0d495
local replay was intentionally interrupted before a final report; its manifest,
sources and component outputs remain retained. A new clean-head replay is
required. No runtime check, instruction behavior or timeout was changed.
