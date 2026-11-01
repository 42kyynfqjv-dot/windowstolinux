# Original argument-configuration and main image name

## Connected result

Original entry under the existing explicit native/UTF-8/CPU/entropy/x87 domains
now executes mode helper `0x40159b -> 0x401bbf` (XOR/INC/RET), pushes its actual
result 1 and calls `0x4015a1 -> 0x4069d4`. The original wrapper restores its frame
and tail-transfers the same activation to `0x4066d6`. The mode-1 path calls the
already initialized original locale function, then `0x406722 -> 0x40ae0d`.

With the additional **`w2l-native-main-image-name-modern-v1`** profile selected
before entry, the original wrapper constructs its 0x22c-byte frame and calls
GetModuleFileNameW at `0x40ae32`, verified IAT `0x415084`. The checked API writes
the actual native snapshot into the original 261-WCHAR local buffer. The
original caller then loads its narrow destination/count, initializes its output
record fields and rejects **before CALL `0x40ae79 -> 0x40ab89`**.

The first onexit registration, original locale state, root startup frame/scope
and preceding stores remain. The narrow destination is still a scalar address
until an actual output operation proves a writable view. No narrow conversion,
argc/argv publication, full initializer return, whole-PE conversion or rcedit
support is claimed. Nonempty onexit decoding/growth/invocation remains unbound.

## Explicit native launch policy

The Linux producer uses `std::env::current_exe()` before guest entry and accepts
only an absolute, valid UTF-8 path without NUL, at most 32,766 UTF-16 units.
It publishes one immutable, process/image-owned UTF-16 snapshot. It does not
reuse argv[0], guess the original Windows source path, use lossy conversion or
claim Windows path spelling/loader acquisition. Supplied model text has a distinct
provenance bit and cannot bind the production API adapter. Default admission and
other profile choices are unchanged.

The token binds the runtime anchor, canonical main-image generation, actual host
PID, publication serial, exact mapping and read fact. Mapping and metadata are
published only after validation; failed publication leaves no issued token.
After startup initialization ends the process-owned snapshot can remain readable.
It is not a borrowed module reference and cannot be freed as an allocation.
Cross-process, stale image/mapping, forged token and intervening source writes
(including an equal-byte write followed by restored permissions) reject. Source
read facts do not reappear merely because bytes compare equal. Process-owned
metadata can be read through another thread view; general concurrency and the
startup-only API adapter remain separate capabilities.

## Bounded GetModuleFileNameW contract

Primary requirement: [Microsoft GetModuleFileNameW documentation](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulefilenamew).
This implements the documented **modern** positive-count main-image case.
NULL selects the current executable; a canonical main-image capability is also
accepted. Numeric handles, unsupported DLLs, zero count, excessive count and
unverified error/resource domains reject instead of inventing Windows results.

For length below nSize, write the UTF-16 units plus NUL and return length excluding
NUL. For length at least nSize, write nSize-1 units plus NUL, return nSize and set
LastError 122. Count is in WCHARs, including the terminator capacity. Surrogate
pairs can be split by truncation; do not silently repair the code units. On
success LastError remains unknown, not an assumed numeric value. Windows XP's
unterminated truncation and unchanged-error behavior are explicitly unsupported.

The adapter checks stdcall argument cleanup, saved registers, protected return,
module identity, output extent/permission and argument aliases before effects.
Only the actual written prefix becomes initialized; tail bytes remain unchanged
or unknown. Live control tags remain protected. Complete data-word overwrites
use the existing 32-bit scalar store to discard old pointer/handle authority.
Partial symbolic-word overwrites remain rejected, as do unsupported layouts;
ordinary scalar data can be overwritten. This does not weaken the general
partial-store primitive or grant pointer authority from the resulting bytes.
Prior effects survive later rejection; missing conversion/error/cleanup contracts
are not replaced with successful callbacks.

## Independent evidence and limits

[Frozen expectations](evidence/argv-expectations.json) and
[results/reproduction hashes](evidence/argv-image-name.json) distinguish:

- 86 modeled UTF-16 output cases across NULL/owned module views, Unicode,
  combining characters, surrogate truncation, full output and unknown tails;
- 17 negative output cases, five failed-publication cases, read-fact invalidation
  and process versus initialization lifetime checks;
- actual Linux current-executable acquisition, never relabeled supplied text;
- 20 checked API/ABI cases, including complete pointer overwrite versus rejected
  partial overwrite, stale/foreign/forged authority, aliases and wrong cleanup;
- five original mode/disabled-mode/invalid-mode/mutated-code cases;
- a Windows-only six-case direct GetModuleFileNameW comparison with the component
  contract. Fresh observations count only after the applicable Windows CI passes;
  they are not unchanged-PE Windows/ELF comparisons.

The retained five recorded original-Windows wrapper comparisons remain component
evidence. There are zero new whole-PE translation pairs. Earlier original-Windows
case 5, case 19, hello and other timeout causes remain unresolved. No timeout,
stack, proof or resource limit was increased. PR #45 stays draft and SUB-579 stays
In Progress.

## Next connected gate / review

Sol review should verify producer versus supplied provenance, read-fact lifetime,
UTF-16 truncation/error ordering, complete-word authority discard, ABI/alias
negatives, original tail transfer and code/import hashes. Then inspect and bind
original `0x40ab89`, its live locale/code-page producer and `0x40ad10` narrow
conversion, preserving failure behavior and record fields. Original count/allocate/
parse and argv storage lifetime remain downstream. Escalate only a concrete
ownership or encoding uncertainty; do not guess ACP or synthesize expected argv.
