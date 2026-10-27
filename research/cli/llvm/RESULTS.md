# Independent compiler results

Freeze commit5058640 precedes evaluation. Source/oracle bytes are identical to the
MSVC stateful corpus; production converter code did not change. LLVM20.1.8 official
archive SHA256:3197846a2b19063687dd56e93e34cd941e3548d907f23a6131571321bdf9fe7b.
Observed clang-cl SHA256:57e32b1ea2456f12f97bf802453171bbff12d56b2c486b4eca0c75343c0cda2c.
The executable is a Windows x64 host compiler; the explicit frozen target produces
PE32/i386. SDK10.0.26100.0, MSVC link14.51.36231 installation; exact paths/hashes,
compiler version, flags and commands are retained in report.json/build logs.

The historical INVENTORY.json comes from run40455323815 at b6e9d0d. Timestamped
PE hashes are per run; Windows/Linux must consume the identical artifact, not
compare separately linked images across runs. All six builds linked successfully.

|Utility|Configuration|First reported conversion rejection|
|---|---|---|
|fold|O1|RVA10ea SETNE AL|
|fold|O2|RVA114c SETNE AL|
|tabs|O1|RVA1094 NOT EBX|
|tabs|O2|RVA10c7 MOVZX EDX,byte [ESP+ECX+10h]|
|escape|O1|RVA10c4 SETNE AL|
|escape|O2|RVA10fc SETNE AL|

Every build passed14 file inputs,14 pipe inputs and3 real OS failure cases:
**186 Windows observations**, empty stderr and exact independently frozen bytes/
exit codes. **Zero translated artifacts and zero Windows/ELF execution pairs** in
this LLVM experiment. Linux reproduces all six rejections on the same PE hashes,
preserving output sentinels. No solver proof was reached; these are decoder-policy
barriers, not measured proof exhaustion or evidence of unsafe programs. Existing
MSVC acceptance and tests remain mandatory. No new scripted cases are counted.

These are first errors in decoder traversal, not a sorted list of unsupported
addresses or the only prerequisites. The complete static inventory also contains:

- MOVZX from initialized frame bytes and high-byte DH, MOV/ADD to DH (overlapping
  partial registers), CMOVAE register32 and SETNE low-byte scalar effects.
- Register-register byte AND and immediate byte TEST; byte knownness must preserve
  untouched bits and flags must be modeled independently.
- Tabs' NOT EBX / TEST BL,3 / restore-next-column idiom. LLVM retains an increasing
  full column counter and observes low bits instead of source-level AND3 after
  each increment. It may wrap over an arbitrarily long stream; no observed finite
  test set proves no overflow. The existing finite0..3 weighted hint cannot simply
  be reused with the unmasked counter.
- JNE counted input loops (rather than JB discovery), rotated read loops with two
  ReadFile sites in tabs, and alternate register/frame placement. Count ownership,
  initialized prefixes and fresh epochs must hold at every site and join.
- Partial-write validation via `written-1 >= remaining` and byte Boolean composition;
  modular arithmetic/refinement must preserve zero-progress and error behavior.

Static instruction presence is not production admission or proof that all forms
are reachable. No PE/source/flag changes were made to bypass these barriers.

## Next integrated gate

Recommend Astra High for a single cross-compiler scalar/control and proof milestone,
with all six frozen graphs inventoried before changes. Define reusable overlapping
byte-register state, memory MOVZX with complete ownership/init bounds, SETNE/CMOVAE,
NOT/TEST/byte AND and modular scalar counter facts. Distinguish scalar wrap from
address/buffer bounds. Adapt independently checked weighted/counted-loop obligations
to low-bit control and rotated reads without assuming stream length below2^32.
Preserve all sources/configurations, genuine failure exits and solver fail-closed
limits. Target186 new same-PE Windows/ELF pairs; if unresolved invariants prevent
that, report exact partial acceptance without a per-fixture shortcut. Independent
unsigned/partial-alias/wrap/zero-progress/stale-epoch/false-invariant negatives are
required. This should be one cohesive architecture step, not a SETNE patch chain.

## Harness and reliability limits

The initial Windows run succeeded. Its artifact included an extraction log at the
runner-temp root, so upload retained an llvm-corpus subdirectory. The initial Linux
path expected report.json at the root and failed before converter measurement;
the harness path is corrected without changing sources, flags or production.
Final-commit CI and raw artifacts are linked in the PR. This harness failure is
retained as history, not a compatibility result.

Seven earlier original-Windows timeout occurrences remain unexplained. No retries,
threshold increases or suppressed failures were added. New LLVM launches retain
stage/command/input/program and partial stdout/stderr on timeout; subprocess.run
cleanup does not supply pre-kill thread/stack evidence, so no common-cause claim is
made. No new LLVM timeout was observed in the initial measurement.
Windows Server2025 is the measured baseline, not XP/7. This selected freestanding
source corpus, shared SDK/linker and one LLVM version do not establish ordinaryCRT,
PE32+, arbitrary I/O/device, general-memory or application compatibility.
