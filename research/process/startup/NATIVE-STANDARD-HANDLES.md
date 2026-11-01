# Native standard endpoints and original descriptor initialization

## Frozen supported contract before evaluation

The explicit native launch metadata profile may additionally acquire real Linux
stdin/stdout/stderr endpoints. The producer clones borrowed standard descriptors
into owned Files before publishing one process table. A failed acquisition drops
only unpublished owned duplicates and rejects; it does not invent Windows NULL,
INVALID_HANDLE_VALUE or LastError equivalence. Other hosts remain unsupported for
this producer. The original native metadata policy still supplies no Windows CRT
inheritance block and is not a Windows startup-data observation.

Each native endpoint has a process-scoped generation and a virtual nonzero handle
value independent of its host fd. Process handle authority is a distinct value
kind from CRT descriptor/record/lock identity. Retrieval copies the process table
without OS validation, duplication or CRT descriptor creation. NULL, invalid and
unchecked numeric table values remain numeric; they never acquire endpoint access.
Closed or uncertain entries can retain numeric bits without retaining authority.
A subsequent type query requires an owned live endpoint. Unsupported host errors
or file types reject without invented Windows results. Linux regular files,
directories/block devices, character devices and pipes/sockets map to documented
DISK/CHAR/PIPE classes; this is a bounded native profile, not universal device or
Windows error equivalence. No device or storage I/O workload is introduced.

CRT descriptor views of a native handle must share its process generation and
revalidate its lifetime. A successful close retires the native endpoint and every
cached descriptor alias. An unavailable observation revokes authority and retains
only cleanup ownership. No stale table entry, file descriptor reuse, scalar cast
or different process may grant access. Missing/invalid table cases in tests are
explicit contract inputs, not newly observed Windows API behavior.

The unchanged 0x4085e7 body is expected to preserve inherited records, query the
three actual standard endpoints, execute its original byte classifications/stores
and return. Callback8 must then execute its own original cleanup/epilog. The next
initializer entry is callback9 at 0x407093 (frozen table index9). Any earlier failure
must retain prior original writes and owned resources. There is no success callback
substitution, change to the PE, or default/full startup/rcedit admission.

Primary contracts: Microsoft GetStdHandle, GetFileType, CloseHandle; Rust AsFd,
BorrowedFd::try_clone_to_owned, File metadata and FileTypeExt. Independent tests must
cover real owned acquisition, fd0 versus NULL, pipe/file classification, retrieval
without validation, NULL/invalid/unchecked entries, cross-process identities,
close/unknown outcomes, replay, aliases, failure ordering and changed original code.

## Observable limits retained

This slice binds GetStdHandle and GetFileType during the declared Linux startup
profile. General SetStdHandle, native CloseHandle/ReadFile/WriteFile, arbitrary
selectors, nonempty Windows CRT inheritance and error translation are not newly
bound. NULL/invalid/unchecked table cases are declared component inputs. A native
acquisition or metadata failure rejects without a fabricated Windows error code.

Owned duplicates pin the native streams. The launcher's original fd 0/1/2 remain
open; model/backend close receipts do not establish complete guest-close/pipe-EOF
semantics. A later native I/O/close adapter must account for **all** retained host
references before claiming externally observable CloseHandle equivalence. Current
startup does not execute that API. Retirement tests demonstrate canonical state
invalidation and actual release/reuse of the owned duplicate, not a new Windows
close/error conformance result. This is a concrete future ownership gate, not a
reason to substitute successful close callbacks in admitted programs.


## Predecessor CI review and repaired test isolation

5ce115c's two Rust CI runs (41253717612/41253713735) passed. Startup inventory
41253713718 failed at native-unwind-slice job124693927907 before any test executed:

```
error[E0433]: cannot find `crt_stream_callees_tests` in the crate root
examples/../src/crt_stream_runtime.rs:1454:12 and :1488:12
could not compile ... (example "unwind_slice" test) due to 2 previous errors
```

The shared runtime file is included transitively by that example, whose crate has
no CRT-only helper module. The new helper-dependent tests moved to the existing
CRT review-test module; the tests remain enabled in their correct suite. The exact
previously failing command `cargo test --locked --example unwind_slice` now passes
185 tests locally. This is a source/test isolation fix, not an infrastructure
hypothesis or a masked retry. The original failed run/log remains evidence.

The new handle slice adds 13 native acquisition/lifetime scenarios, one atomic
publication/duplicated-file/reused-fd sequence, and nine original-body scenarios.
The native sequence forces an actual Linux fd reuse and checks that the old token
stays rejected. Body cases require successful normal/shared/NULL-invalid returns
and exact negative outcomes for unvalidated values, stale receipt, ended init,
changed code/import and unknown close; prior stores survive later failures.
The complete original-entry case checks the next callback target, released outer
lock and all 64 descriptor records. Fixture assertions were updated for the newly
completed callback, and the standalone caller explicitly binds original RET0.
No guest permission/return check was weakened to make those tests pass.

## Next bounded integration and review

Review process-handle versus descriptor authority, pinned resource ownership,
retrieval without validation, failed publication, stale/unknown-close handling,
fd reuse and ABI/partial-effect ordering. Keep the Linux-only producer distinct
from Windows baselines and supplied NULL/invalid table inputs. Audit the transitive
example test-isolation fix and exact-head CI separately.

The next original callback is 0x407093 (25 bytes); its first operation is named
GetCommandLineA at IAT0x41508c, followed by GetCommandLineW at IAT0x415090. A cohesive
Sol implementation can establish lifetime/initialization for both process-owned
strings and their original stores. It must declare how native argv maps to a
Windows-style command line and how narrow/wide encodings agree, reject unsupported
input rather than guess codepages, and preserve original raw-command-line versus
argv distinctions. No escalation is needed just for CI or this inventory. A future
close/I/O backend needs a separate concrete ownership decision about all retained
host fd references before claiming pipe-EOF equivalence.

## Recoverable implementation checkpoint (historical)

Local verification passed 296 CRT tests (two artifact tests omitted in the ordinary
suite), the artifact-backed canonical entry/body test including all nine new cases,
185 unwind-slice tests, 76 Python tests (one existing skip), Clippy and formatting.
At fc9093e, the broader replay was not yet accepted: its last inline-exit native link failed
with `ld` signal7/Bus error while the workspace disk became full. A subsequent
sandbox start explicitly failed ENOSPC. The failed logs/source are retained; this
is separate from all historical original-Windows timeouts. Disk recovery removes
only regenerable compiler cache/build output or compresses old generated native
binaries with round-trip hash verification; source, original PE and Windows failure
evidence stay intact. A fresh complete replay/report remains required.

Other connected-fixture inputs remain explicit: the parent activation/thread-chain
premises and the CPU/entropy test environments are not discharged by acquiring
native standard endpoints. The replay therefore remains original-instruction
component evidence, even though the new endpoint/type producers use real OS state.


## Accepted final local replay

A fresh complete replay passed with unchanged source and limits after resource
recovery. Both artifact-dependent tests completed. A later explicit emission
advanced mtime and matched generated Rust SHA-256
`e9b4ac51302809bb6971674c39a8394f8bbad478f68b1ef0ec2022d88f840a6e`.
The unchanged PE SHA-256 remains
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`.
The report retains five recorded Windows wrapper comparisons, with zero new
Windows observations, Windows/ELF pairs or whole-PE pairs. Nine Linux-only new body
cases are reported separately. The first failed replay/decoded CI log and the
historical Windows timeout remain preserved; no threshold or original expectation
was relaxed to obtain the final result.

[Exact source/report/log hashes and review findings](evidence/native-standard-handles.json)
include all final gates (296 CRT, 185 unwind, 76 Python/one skip, Clippy/format), the
cross-example CI regression and repair, and the local resource interruption.
Checkpoint workflows 41256060511/41256056609/41256056664 were still running at
publication of this evidence; final-head CI must be checked separately. No merge,
formal approval, default admission or full startup/rcedit support follows.
