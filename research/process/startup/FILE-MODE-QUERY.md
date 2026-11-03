# Original file-mode lookup and UTF-8 query

## Connected result

With an additional explicitly selected native process file-mode policy, original
entry resolves `AreFileApisANSI` through the real shared kernel32 resolver,
publishes its typed function cache under the existing lock/page protocol,
executes the original guard and indirect call, and completes locale helper
`0x40ab89`. The unchanged locale-info code page is still not 65001: its actual
branch selects CP_ACP=0 for ANSI, or CP_OEMCP=1 for OEM. Neither is replaced by
GetACP's numeric result. The configured Linux entry test explicitly selects ANSI;
the default platform does not acquire a file-mode result automatically.

Original `0x40ae94 -> 0x40ad10` now executes the real conversion query, original
flags helper `0x40b835` and WideCharToMultiByte wrapper `0x40b8c5`. Its first
API call `0x40b924` returns the actual required UTF-8 byte count under the
already declared process encoding. The original caller compares capacity and
executes write wrapper `0x40ab65`. The next rejection is the **second API call
at `0x40b924`, with output capacity 260**, because conversion writes remain
unbound. The live frame, output record, onexit and earlier startup effects remain.
No narrow output, argv publication or image-wrapper completion is claimed.

## Process state and BOOL knowledge

`w2l-native-process-file-mode-v1` selects ANSI or OEM explicitly before entry.
Canonical runtime state owns this policy for the process, across thread/fiber
views; it is independent of ACP and module references. The implemented getter
export borrows a live native kernel32 provider. Lookup, original guard and actual
call revalidate the matching symbol/function/provider, and the guard receipt is
single-use. Unconfigured, stale, foreign, wrong-function and malformed ABI states
reject. Native provider export storage now reserves a third entry before guest
entry; allocation failure is component rejection, not a Windows API result.
This initializes a Rust replacement namespace, not a Windows DLL or loader state.

OEM returns known zero. ANSI issues a fresh **nonzero scalar symbol**, not the
number 1 or an invented known set bit. The shared full-width TEST operation can
establish ZF=false for the same symbol; its sign remains unknown. Different
nonzero results may have disjoint set bits. Partial registers lose this fact.
Full-word transport retains identity but marks backing bytes unknown, so raw or
partial reads cannot expose a placeholder zero. Numeric/address conversion
rejects. These are ordinary data values, not pointer or restoration authority;
they do not expire merely because the original API provider unloads.

## Bounded UTF-8 query

The API adapter supports flags 0, input count -1 or positive 1..32767, NULL
default/used-default arguments, and **zero output capacity**. It reads exactly
the selected owned UTF-16 units, replaces unpaired surrogates with U+FFFD, and
counts UTF-8 bytes. A -1 count includes the first NUL; a positive count processes
exactly that many units and adds no NUL. Unknown/stale input rejects. The unused
output argument is not dereferenced or initialized, including a non-NULL query
argument. The result grants no writable pointer or later copy receipt.

CP65001 is explicit UTF-8. CP_ACP=0 requires the canonical process encoding token
and live narrow/wide snapshots from the existing UTF-8 launch contract. This is
not the Windows host's ACP. CP_OEMCP=1, strict/error flags, non-NULL default output,
conversion writes, capacity growth/reset/free and error/errno effects remain
unbound. Source lifetime and partial-write behavior must be closed before those
paths can be admitted; successful size queries do not certify a later copy.

## Demonstrated output-word integration fix

Actual resolver cache publication exposed a reused stack slot containing an old
ordinary data-pointer tag. The successful VirtualProtect four-byte output can
now overwrite that complete data word and discard its old authority. Partial
tag overwrites, live saved/return/thread/dispatcher tokens and unsupported roles
still reject. The memory operation validates and commits page/output effects
atomically; tags clear only after success. Five independent cases check complete
pointer/nonzero words, partial overlap, control state and failure atomicity.

## Independent observations and scope

Predecessor `4474da6` passed all three workflows. Windows run **41324424142**,
artifact **13091510713**, retains two independently collected complete 15-case
API traces with identical hash
`66b6a3c650413b25f6494901f61fde3f60a36c053c31572665b2747e059faad6`.
The reproduction report hash was checked against the raw trace. One copy is
[retained here](evidence/file-mode-conversion-windows-4474da6.jsonl).

This x86_64 Windows host reported ACP1252/OEM437 and exported AreFileApisANSI
from KERNEL32.DLL. These observations do not establish XP/7 behavior or a
universal export owner. The native replacement uses its declared provider.
The trace confirms **error1113 after writing replacement bytes** for invalid
strict UTF-16, and error122 with an already written UTF-8 prefix for insufficient
capacity. It repeats the earlier flag0x10 return2 observation. Unsupported flags
remain excluded; no unchanged-buffer or atomic-failure fiction is introduced.

The Windows job rebuilt its own authored PE; that full binary hash differs from
the local frozen artifact. Its guarded original regions and emitted Rust match
the predecessor local source. The API observations are direct original-Windows
calls; local query/BOOL cases are native components. Five retained wrapper
comparisons are also components. **Zero new whole-PE pairs.** Full startup,
rcedit/default admission and all historical timeout causes remain unresolved.

## Reviewed local verification

182 root, 332 CRT and 185 unwind tests passed; both ignored artifact gates were
separately executed in the complete replay. Python checks passed: 96 startup
(one skip), 106 tools and 18 corpus (one skip), plus Clippy and formatting.
Fresh current-source emission is byte-identical to the reviewed full replay:
`9638da15f369b2625e4cbb7fd6ce918dc9e1586b1f822e54a9881e5fb510c616`.
The initial partial local replay was stopped and retained when review replaced
the symbolic storage sequence with a single atomic forget; that partial run is
not counted. The complete reviewed replay uses commit c2f2445. Fresh final-head
CI remains separate, and no old run or component observation is a whole-program
support claim.

[Frozen requirements](evidence/file-mode-expectations.json),
[verification/provenance](evidence/file-mode-query.json), and the
[dependency map](DEPENDENCIES.md) retain exact boundaries. Sol can review these
shared semantics. The next connected implementation is the output write, source
lifetime/alias contract and growth/error effects, then original stores/cookie
return and argv parser; it must preserve the measured failure writes.

## Primary contracts

- [AreFileApisANSI](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-arefileapisansi)
- [SetFileApisToANSI](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileapistoansi)
- [SetFileApisToOEM](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileapistooem)
- [WideCharToMultiByte](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte)
- [VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
