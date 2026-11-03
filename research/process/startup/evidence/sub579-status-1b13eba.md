# SUB-579 status preserved before inline-exit update

## Current status

[SUB-579](<https://linear.app/substratequantum/issue/SUB-579/close-a-shared-startup-and-pointer-record-dependency-from-unchanged>) remains In Progress; PR #45 is draft, open and unmerged. Published and remote-verified checkpoint: 1b13ebacdd7625e36263c89e4596b582445cfb0c.

Original abort decisions now execute after the registered locked query: nonzero selects actual signal22 dispatch, zero tests module flags and selects feature23 or the original exit wrapper. The exit wrapper reaches shared exit406e69 with actual status3/mode2/zero arguments. Missing signal/API/exit effects always reject. Full startup/rcedit remains unsupported.

## Durable evidence and history

* <pull-request id="019b0b8c-1ecc-44a9-9d72-3d8e5bc86a5e" href="https://linear.app/substratequantum/review/sub-579-checked-startup-records-cookie-domains-and-unresolved-bc9b5803315e">SUB-579: checked startup records, cookie domains and unresolved exception boundary (in progress)</pull-request>
* [Current implementation evidence and limitations](<https://github.com/42kyynfqjv-dot/windowstolinux/blob/feature/startup-records/research/process/startup/LIVE-FINALLY.md>)
* [Preserved prior issue description](<https://github.com/42kyynfqjv-dot/windowstolinux/blob/533558e/research/process/startup/SUB-579-HISTORY.md>)
* [Entry-to-exit integration plan](<https://github.com/42kyynfqjv-dot/windowstolinux/blob/feature/startup-records/research/process/startup/ENTRY-TO-EXIT.md>)
* [Remaining callbacks, API assumptions and next cohesive formatter scope](<https://github.com/42kyynfqjv-dot/windowstolinux/blob/feature/startup-records/research/process/startup/REMAINING-CALLBACKS.md>)

The historical description was preserved verbatim before this replacement. It contains prior checkpoints, contracts, CI references and adversarial evidence. Repository records are authoritative for detailed counts and hashes; component execution must not be counted as whole-PE translation.

## Remaining work and acceptance

1. Establish original locale/FILE producers and external effects, then connect the complete formatter driver/parser/integer/output/destruction on the same live owner. Native printf wrapper/accessors are connected. Preserve nested frame/lock ownership, short-write/error/flush effects and earlier effects on later failure; no projected-image or expected-output substitute.
2. Connect remaining original outer-frame invocation and entry/module/thread conditions to the live Main path. Reporting and epilog now execute within the documented component inputs; remove those cuts only when supported by original instruction/effect proof.
3. Retain same-event capture lifetime, source/target identity, single-use receipts, initialized full bounds and live-memory coherence across nested dispatch, cleanup and restoration.
4. Prove actual Windows delivery acquisition, incoming-handler containment and RtlUnwind/collided-unwind effects for every newly admitted domain. Supplied delivery/context cuts remain explicit assumptions.
5. Require unchanged PE/source/toolchain provenance, deterministic generated Rust, real Windows/ELF stdout/stderr/exit evidence and independent malformed/alias/lifetime/replay/failure tests before claiming end-to-end support.
6. Required final-commit CI and substantive review must pass before merge. Historical original-Windows timeout failures remain preserved and unexplained; a later passing run is not a diagnosis.

## Verified checkpoint evidence

240 CRT tests passed (one vector-dependent test ignored in the suite, passed separately in retained replay), 175 converter tests, Clippy, formatting/diff checks and 60 Python tests (one existing skip). Replay passed five recorded Windows wrapper comparisons, 85 ordered cases, 16 registered-errno cases, 12 locked-query cases and 13 new branch cases. No new Windows observations or whole-PE pairs.

Independent review reran the old lock-guard mutant and reproduced wrongful release; corrected ownership tests pass. New cases retain unknown relevant bits, ignore no unknowns, reject stale flag storage/process/thread changes and missing protected return, preserve prior writes, and assert actual22/23 and3/2/0 argument words. A test-only closed-runtime expectation was corrected: ordinary reads reject after closure, so retained backing bytes verify the prior write.

PE SHA256: 1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4. Rust SHA256: 8d763d3b0b1c60836bd396bc1d7cefc76b99b96bf3868e3950b7ff2eb00cf2e1.

[Connected original branches and remaining gate](<https://github.com/42kyynfqjv-dot/windowstolinux/blob/1b13ebacdd7625e36263c89e4596b582445cfb0c/research/process/startup/CAPTURE-ACQUISITION.md#original-abort-branches-and-exit-wrapper>) · [Review, hashes and provenance](<https://github.com/42kyynfqjv-dot/windowstolinux/blob/1b13ebacdd7625e36263c89e4596b582445cfb0c/research/process/startup/evidence/abort-branches-review.json>) · [Dependency map](<https://github.com/42kyynfqjv-dot/windowstolinux/blob/1b13ebacdd7625e36263c89e4596b582445cfb0c/research/process/startup/DEPENDENCIES.md>)

## CI and preserved failures

Current 1b13ebacdd7625e36263c89e4596b582445cfb0c:41008206058 in progress;41008202279/41008202171 queued. No final-commit CI success claimed.

Reviewed db8d128: pinned41006631527 success; Rust41006636984/41006631641 still in progress. No observed new failure at readback; these are predecessor checks.

Reviewed14f7299: push workflows41004977851/41004977944 success. PR41004981995 failed authored-windows-fixture job123897726848: original imported untaken fixture process.wait exceeded15s. PE SHA256 b5a3bb8ee10c6ca16d5b9b2b53e39bc214d6fc4a6e6977a1fdf20a7dc7675554. Imported-launch artifact12955196422 ZIP SHA256 a1911ff7c4d7c42a5f7fef5eeff78eaf83e88a6e52760f2f0c61610359876f31. Logs do not establish untaken output or cause. No retry/timeout relaxation; this remains distinct from semantic tests and earlier failures.

Reviewed7f206c2: all three41003579881/41003575818/41003575835 completed successfully. This does not diagnose historical failures.

Reviewed abb3744: all three41002080357/41002074502/41002074539 completed successfully. This does not diagnose historical timeouts.

Reviewed 3c02eff completed all three workflows successfully: 41000164833 / 41000160050 / 41000160056.

Reviewed 223938e completed all three workflows successfully: 40997493851 / 40997489151 / 40997488681. This does not diagnose historical timeouts.

Reviewed 1788a76 completed all three workflows successfully:40995444671 / 40995440369 / 40995440136. This does not diagnose historical timeouts.

Predecessor db4fc00: Rust push 40993129680 passed. Pinned 40993129755 failed after 226 CRT tests passed: its comparison runner still required eleven selected tests after a twelfth was added. Replaced the stale count with named completions and a consistent successful summary, with independent false-pass regressions and passing local replay. PR40993135963 separately failed an original-Windows helper process.wait timeout (job123860002538, artifact12949818169). This remains unresolved and is not diagnosed by the count fix. [Preserved logs/artifact references](<https://github.com/42kyynfqjv-dot/windowstolinux/blob/1788a76afbdc66895af893471a100de9b33eb491/research/process/startup/evidence/ci-db4fc00.json>).

Reviewed 5c9d4c2 completed all three workflows successfully:40991613100/40991607698/40991607746. These predecessor results do not validate the new review head or diagnose historical Windows timeouts.

Reviewed d192385 completed all three successfully:40989022050/40989017448/40989017442. c3be6ab also completed all three successfully:40988106192/40988100925/40988101018. These predecessor conclusions do not validate the new head or diagnose historical timeouts.

Reviewed 5615c2b completed all three workflows successfully: Rust40984728593/40984721250 and pinned40984721318. Reviewed72974f0 push40983899668 and pinned40983899745 passed; PR40983904709 failed the original-Windows output-probe timeout at job123830245636. The failure was process.wait after 15 seconds; output bytes/root cause were not established. Artifact12945762783 zip SHA256: 96dfadc2a100625596ee5de92de395a9252171aec384ff1b516bf2865a799149. No retry or timeout relaxation was used. A successful parallel run does not diagnose it.
[Preserved output-probe evidence](<https://github.com/42kyynfqjv-dot/windowstolinux/blob/c3be6aba931cc1ac3b0a0e703aa3a6013cd73b41/research/process/startup/evidence/windows-output-probe-72974f0.json>)

Reviewed 3984666: pinned 40982784708 passed; Rust 40982789204/40982784727 still in progress. Reviewed 2cc9c77 completed all three successfully: 40981470017, 40981463218 and 40981463168.

Reviewed 36eeb34 completed all three workflows successfully: 40979161128, 40979155479 and 40979155599. These exact predecessor conclusions do not validate the changed capture-view head or diagnose historical timeouts.

All three workflows for reviewed214d585 passed:40971700846/40971694667/40971694772. All three forcfaa71f passed:40972514039/40972507526/40972507509. These are predecessor results.

Predecessor1a7b985: all three workflows40956757366/40956747335/40956747197 completed successfully. All three8949d0f workflows40955306382/40955299050/40955299037 also completed successfully.

fe0d0dc run40949077644 attempt1 failed artifact creation with ECONNRESET, leaving later comparisons skipped. Its explicitly labeled failed-job infrastructure retry passed as attempt2 (Linux job123720191590). That validates the old retried run and does not erase attempt1.
[Preserved upload failure and retry](<https://github.com/42kyynfqjv-dot/windowstolinux/blob/8efaffc2d0724a25f3b43b9482b466f085f11f0a/research/process/startup/evidence/upload-reset-fe0d0dc.json>)

Historical original-Windows process-exit timeouts remain separate and unexplained, including hello5c3c2b5 PR40939364543/job123678335203 and earlier case24/case16. Passing runs do not diagnose them.
[Preserved hello evidence](<https://github.com/42kyynfqjv-dot/windowstolinux/blob/8efaffc2d0724a25f3b43b9482b466f085f11f0a/research/process/startup/evidence/windows-hello-5c3c2b5.json>)

## Next connected scope

Review1b13eba branch/exit lowering and strict missing-effect rejections; verify final CI. Actual next exit target406e69 uses an inline FS record at EBP-12 with handler414af3, try level,24 locals and cookie. This differs from the proven EH4/helper saved-register layout. Conditional normal return unlinks the record; the process-termination path skips that epilog. A bounded Astra pass is justified to establish canonical registry ownership, byte image and lifetime across return/nonreturn/failure, without relabeling this as414ad6/EH4.

Freeze mode2 reachable exit graph/API arguments before mapping physical termination. Signal22 dispatch40cc14 and encoded callback/default/ignore behavior remain a separate unbound path; feature API41501c, fast-fail/reporting and full exit effects remain unsupported. Initial abort flags/module/lock/FLS state and actual Windows delivery remain supplied or unproved.

Keep PR45 draft and <issue id="4c595c7a-20ac-42c4-b549-8e0965039994" href="https://linear.app/substratequantum/issue/SUB-579/close-a-shared-startup-and-pointer-record-dependency-from-unchanged">SUB-579</issue> In Progress. Full startup/rcedit and historical Windows timeout causes remain unresolved. No formal approval or denied optional comment was submitted.
