# SUB-551: isolated bounded native acquisition

Historical design/component checkpoint: production integration is now specified in
[SUB-552 INTEGRATION.md](INTEGRATION.md). Statements below about blocked emission
refer to that earlier phase; these artifacts alone still grant no eligibility.

`examples/bounded_input.rs` implements local Linux input acquisition for the frozen
freestanding environment-input experiment. It is an isolated component, not
emitted by the converter and not an eligibility certificate. The input PE and
ordinary CRT programs remain rejected. It contains no unsafe blocks, foreign
pointers, decoder dependency in its source, interpreter or AI runtime.

## Mechanism and domain

The Linux [proc_pid_environ manual](https://man7.org/linux/man-pages/man5/proc_pid_environ.5.html)
documents a NUL-separated initial environment set at execve, which does not reflect
later environment changes; a process can also relocate the referenced region.
Access is permission-controlled. We read only `/proc/self/environ`. A genuine
available procfs, ordinary own-process access, stable initial environment memory,
no relocation or post-launch environment mutation are explicit host premises.
No privilege or system setting is changed. Unavailable/non-Linux/read failures
return an unsupported-host error. There is no fallback to unbounded stdlib reads.
The component cannot detect that a caller previously mutated its environment;
production integration must prove the admitted program has no such effect.

Windows reads its current UTF-16 environment. Under the reviewed stable launch
domain this maps to Linux initial UTF-8 bytes. This is not general Windows
case-insensitive environment emulation. All admitted names are nonempty ASCII;
only exact uppercase `W2L_INPUT` may match, with any ASCII case alias or duplicate
match rejected even if values agree. Non-ASCII names reject, preventing an
unproved Unicode case-folding alias. Other values may contain arbitrary bytes;
they are never decoded, returned or logged. The selected value must be strict
UTF-8, hence no encoded lone surrogates. NUL separates records and cannot be part
of a represented value. Empty/missing is valid and distinguishable internally.

The manual permits a final record without trailing NUL. This component deliberately
requires a final NUL for a nonempty snapshot and rejects an unterminated snapshot;
it does not call every such Linux snapshot malformed or silently invent termination.
Empty snapshot is a valid missing-variable environment. Empty records, missing `=`,
empty names and excessive records reject. Validation continues after finding the
key, so a later alias, duplicate or structural failure cannot be hidden.

## Fixed resource limits

| Resource | Limit |
| --- | --- |
| Complete snapshot bytes | 65,536 |
| Storage including overflow sentinel | fixed 65,537-byte stack array |
| Records | 256 |
| Record bytes excluding NUL | 4,096 |
| Read attempts including interrupted/EOF calls | 1,024 |
| Owned selected value | fixed 64 UTF-16 units (128 bytes) |
| Projected application buffer | six optional bytes |

One extra input byte detects total overflow. The read loop handles short reads,
counts interrupted attempts and rejects broken reader lengths without unchecked
indexing. [Rust Read](https://doc.rust-lang.org/std/io/trait.Read.html) allows short
reads, EOF and interruptions; it gives no wall-time guarantee. A stalled OS read
is outside this byte/attempt bound; process probes retain a10-second timeout.
A very fragmented source may hit the attempt cap before its byte cap; this is an
explicit host rejection. We do not claim a bounded wall-clock syscall or silently
raise timeouts.

Parsing/UTF conversion borrow the bounded snapshot, then copy at most64 units to
an owned fixed array. No input-sized Vec/String allocation occurs in the component.
UTF-8 validation examines at most the bounded record, and UTF-16 conversion stops
at the65th unit. This is a structural bound on component-owned input storage,
not on Rust startup, OS file internals, compiler stack-frame layout or total
process memory. A sufficient native stack and normal no-fault execution remain
premises. Tests may allocate synthetic data; that is not the production reader.
`std::env::var` was declined because it copies an arbitrary value first. Borrowed
libc pointers were declined because their mutation/lifetime proof would add unsafe
obligations. Procfs availability and initial-state semantics are the chosen tradeoff.

## Result and initialization semantics

Acquisition returns a private owned `Value` or typed `Error`. Errors include
unavailable/IO, read budget, snapshot/entry/value limit, unterminated/malformed,
case alias/duplicate and encoding failure. They never become raw Windows API
return0. The isolated driver projects every host error to diagnostic exit203 with
empty output, matching the frozen resource/encoding policy; internal error kinds
remain distinct. This is not a generic GetLastError implementation.

On successful acquisition, `project()` constructs a separate conditional result:
missing/empty -> return0 with all six bytes unknown; one/two units -> return1/2
and exactly4/6 initialized bytes including little-endian UTF-16 NUL; three through64
units -> required capacity(length+1) with all bytes unknown. No truncation buffer is
readable. Unused backing-array zeros do not confer initialized-byte authority.
Value65 or invalid encoding fails acquisition and never manufactures a raw API
success. The small program projection reads only initialized success units,
validates ASCII digits and computes the frozen exit result. The compiler's prior
intermediate LEA wrap remains valid modulo2^32 as documented in MODEL.md; this
component does not replace those instructions in a translated program.

## Evidence

Eight new Rust test functions exercise exact/one-over snapshot, record and UTF-16
limits; initialized bytes/terminators; Unicode surrogate-pair counting; invalid
UTF-8/surrogate encodings; ASCII aliases/duplicates/non-ASCII names; malformed and
unterminated records; failure after a found key; unrelated binary values; short
reads, IO/interrupted budgets and invalid reader sizes; owned result survival after
source mutation. These are component tests, distinct from eight inherited model
tests and79 root Rust tests.

`check_acquisition.py` launches the SAME component binary with17 frozen environments
and compares exact stdout/stderr/exit with independent expectations and the original
Windows artifact report. Five additional Linux host-domain rejections cover invalid
UTF-8, lowercase alias, dual-case match, oversized unrelated record and non-ASCII
name. Neither these probes nor the original separate Rust prototype are PE->ELF
conversion. The report records original PE, component source and component binary
hashes; no ambient environment contents are persisted. Source/flags/vectors of the
Windows program remain unchanged. Existing12 compiler102 authored18 launch checks
and four held-out rejections remain distinct. Four historical process timeouts are
unresolved; Windows Server2025 is not XP/7 validation.

Run `cargo test --locked --example bounded_input`, build the same example, and run
`python3 research/input/check_acquisition.py EVIDENCE`. CI compares against the same
hashed Windows PE and uploads `input-acquisition.json` from the Linux job.

## Next integration gate

After medium review, integrate only through a private production certificate:
strict PE metadata/import/name/relocation binding, live owned six-byte local with
protected stack exclusions, stdcall cleanup and saved ESI, symbolic API length
and guarded initialization, exact16/32-bit compiler forms and modular LEA semantics.
The output must acquire data at runtime and retain all branches, not specialize to
these17 examples. Check deterministic emitted Rust under different converter
environments, then run the same actual ELF against all17 Windows outcomes and
adversarial metadata/guard/buffer/alias cases. Failed proof has no fallback.
Host procfs/stability/resource premises must be carried into the generated runtime
contract explicitly. No general CRT, dynamic execution fallback or broad memory
support follows from this isolated component.
