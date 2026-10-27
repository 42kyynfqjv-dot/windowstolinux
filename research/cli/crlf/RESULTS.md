# Stateful CRLF measurement result

Sources/configurations and independent expectations froze in813a419/2a45541
before evaluation. CI40441853363, measurement commit d5d16ea: both unchanged
O1/O2 builds pass78 real Windows file/pipe/failure observations.24 separately
scripted backend records pass:20 chunk/EOF schedules and four read/write/progress
failures. These are not additional OS scheduling observations or ELF translations.
Windows Server2025/build26100; exact compiler version/commands are in build logs.

**Zero ELF translations.** O1 rejects at RVA1091, CMOVE ESI,EDI. O2 rejects at
scalar-store aliasing of the read-epoch length cell (RVA107b zeroes n after EOF).
Both hosts must agree on exact rejection and unchanged PE hash. INVENTORY.json
records the measurement run's full instruction list, sections, hashes and outcomes;
each future CI run inventories its own timestamped unchanged binaries.

Both builds allocate280 local bytes, with separate input128/output129 arrays,
scalar words, saved registers and five external calls. O1 has conditional selection
of the end flag; O2 spells it with branches. Both carry pending CR across the outer
read loop, construct output using separate input/output indices and append a lone
CR at successful EOF. Stores of literal CR initialize new output bytes. Scalar
stores to n are legitimate program behavior but currently violate the intake's
unique-writer optimization; this is a conservative support limit, not a mistranslation.
No production decoder/proof/runtime changes were made to fit the experiment.

## Next cohesive implementation gate (Astra High)

1. Model independent owned input/output regions, initialized extents and lifetimes.
Fresh reads invalidate input initialization; output stores must prove append/overwrite
bounds without gaps or aliasing words, input, returns or metadata. Output capacity129
must prove sufficient for n+1 including carried CR and EOF flush. Old output bytes
must not fabricate fresh input facts.
2. Decouple the proof's fresh-read initialized length from writable guest n. Manual
n=0 on EOF must neither create initialized input nor retain an old-read capability.
Keep all count-word/buffer ranges and failed-read semantics checked. Do not just
remove the unique-writer check while prefix and count share one symbolic variable.
3. Represent pending/end state and input/output indices soundly across loop joins;
prove initialized output length and final flush, including CR at every boundary.
Normalize exact CMOVE register form with preserved flags and conservative value/
initialization joins; unselected/unknown source assumptions need explicit proof.
4. Require both unchanged originals and78 real Windows/ELF matches with identical
Rust/hashes, separately scripted read/write schedules/errors, independent wrong-owner,
overlap/gap/uninitialized/stale-epoch/EOF-flag/unknown-condition negatives and prior
corpus. Preserve solver budgets/reject-unknown, no fixture-graph shortcut or runtime
interpreter. Report partial outcomes if a proof remains unresolved.

The selected18 vectors and finite schedules cannot establish all-input equivalence,
OS partial-I/O behavior or termination. Missing-handle10 and malformed count14 are
contract boundaries, not claimed real observations in this corpus. Real permission
failures/closed pipe are counted separately from backend substitutions. OrdinaryCRT,
general memory/devices/async/XP7 remain unsupported; historical five Windows timeout
causes stay unresolved. No source revision, compiler-flag tuning, binary surgery or
support expansion was used during measurement.

Reproduction: python research/cli/crlf/measure.py <dir> in x86 MSVC shell; download
that exact artifact and run python3 research/cli/crlf/check_native.py <dir> on Linux.
Primary contracts: Microsoft ReadFile/WriteFile/GetLastError documentation; successful
file EOF and broken byte-pipe EOF are distinguished. Probe is an ordinary-CRT-linked
authored harness with substituted API functions; only the frozen freestanding
originals are converter targets.
