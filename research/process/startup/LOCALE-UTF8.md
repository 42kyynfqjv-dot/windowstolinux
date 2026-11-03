# Original UTF-8 initializer and classifier

This records the `c0d42a7` checkpoint. [LOCALE-RESULT.md](LOCALE-RESULT.md)
documents the next connected caller advance and corrects the earlier description
of `0x407126`: it exchanges a flag and does not acquire a lock.

## Executable boundary

The opt-in native UTF-8 environment now executes the original
`IsValidCodePage` CALL `0x40b4e6`, the UTF-8 stores in initializer `0x40b485`,
classifier `0x40b090`, both cookie checks through `0x40154c`, and their original
returns. The original caller rejects at **`0x40b2cc`**, before interpreting the
result, replacing references, publishing locale state or completing cleanup.
Entry still has initialized flag `0x41d148 == 0` and unchanged old references.
The second selector's actual clear of `0x41d144` remains visible.

These are connected original-instruction components from the frozen authored
`unwind.exe`, not whole-PE conversion or full rcedit support. Default admission,
other code pages, GetCPInfo/NLS, reference freeing, malloc errno/new-handler and
exceptional EH4 cleanup remain unsupported. Other delivery/resource/encoding and
native close/EOF equivalence gaps in the dependency map also remain open.

## Independently frozen API observations

The old probe normalized BOOL to 0/1; it could not establish the raw return word.
It remains unchanged. A [separate raw probe](code_page_raw_probe.c),
[expectations](code-page-raw-expectations.json) and
[freeze](code-page-raw-frozen.json) were pushed at `9664382` before binding.
Windows job [124777199658](https://github.com/42kyynfqjv-dot/windowstolinux/actions/runs/41282533822/job/124777199658)
compiled and ran it using official MSVC 14.44.35207 x86/SDK 10.0.26100.0 on
Windows Server build 20348. Raw results were 1 for 65001 and 0 for UINT_MAX.
Observed ACP was **1252**; LastError remained `0x12345678` in these two samples.
Compiled/executed PE and frozen input hashes are retained in the evidence JSON.

The explicit contract `w2l-native-installed-codepages-20348-raw-v1` supports
only those two queries. All other queries reject; an unsupported encoding never
becomes an invented FALSE. Installed-code-page availability is separate from the
existing explicit ACP 65001 environment. No target ACP, XP/7, or arbitrary Windows
installation behavior follows from this observer.

[The public API contract](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-isvalidcodepage)
does not promise LastError preservation. The binding invalidates that knowledge,
clobbers volatile registers/flags and performs checked stdcall-4 return. It
requires matching process/provider/initialization lifetime, active protected call,
known scalar input and unchanged saved registers. Observations are API conformance,
**zero new translated Windows/ELF pairs**.

## Original byte effects and authority

The entire original helper bytes and executable mapping are checked at entry;
the IAT binding is checked at the actual API call. Original loops derive ASCII
classification bits and case mappings. No output table or precomputed locale
result substitutes for those instructions. Stores initialize only actual written
bytes/bits; untouched unknown bytes stay unknown. Caller and initializer ownership
remain distinct: the caller initializes the reference count, while initializer
offset 24 is a DWORD store and offset 28 a WORD store.

One original ADD at `0x40b1ef` computes a numeric byte index by cancelling a live
buffer address. A shared IR qualifier permits register ADD/SUB to produce a scalar,
using original arithmetic/flags. It validates source lifetime and **drops result
authority**. It cannot qualify memory operands, ESP/EBP destinations, LEA/MOV or
other operations; generic checked pointer arithmetic is unchanged. Even a result
numerically equal to another allocation cannot address it. Unknown bits and stale
sources reject before register/flag changes.

Cookie mismatch takes an explicit unsupported failure boundary; it cannot become
a successful RET. Each normal return consumes the original protected token and
validates nonvolatile state. No exceptional return or unproved cleanup is admitted.

## Independent regressions and failure ordering

The artifact replay executes 49 initializer cases: four disjoint bases (including
high 32-bit addresses), initialized/unknown data, forged/released/truncated buffers,
non-UTF8 query, changed helper/guard/initializer/IAT, missing profile, typed aliases,
and a mismatched cookie. Strict result/byte/state assertions preserve prior effects
on later failure. A stale pointee can be transported as an argument; its first
dereference rejects **after** the preceding API, retaining that API's unknown
LastError. Earlier setup attempted to mutate readonly IAT bytes after mapping;
the corrected case mutates the input PE before checked mapping. No permission
restriction was relaxed.

Fifteen isolated API cases cover process/thread/fiber ownership, lifecycle, ABI,
replay, unknown or typed inputs and out-of-profile queries. Numeric arithmetic
has 21 value/flag vectors, 21 stale-source cases, independent alias/unknown cases
and rejected instruction forms. All 152 preceding word cases and REP failure/
progress regressions are retained. Full replay separately requires named tests;
the five recorded Windows wrapper comparisons remain component comparisons, with
zero new whole-PE pairs. See [evidence](evidence/locale-utf8.json).

## CI failures remain evidence

Review confirmed all three `63b4afb` workflows green, including Windows execution
of all 152 repaired word cases. The preceding stack overflow is preserved;
generated case frames were split without raising limits.

At interim probe commit `9664382`, push Rust `41282533828` and startup
`41282533822` passed. PR Rust `41282537080` failed its **original imported hello**
launch, job `124777208552`: expected `Hello`, empty stderr, PID/creation-verified
process still alive after 15 seconds, then killed/reaped. Artifact `13074246257`
contains original PE and observer evidence. The fixed diagnostic plan passed 9/9
on the same run; no cycle was reported, which does not establish a cause.
This distinct Windows-2025/image `20261030.294.1` occurrence does not prove an API
or UTF-8 loop failure and is not erased by other passes. Earlier 6daf5ad,
historical case-19 and other original-Windows timeout causes remain unresolved.

Next: execute original caller result handling at `0x40b2cc`, then checked
reference replacement/publication and cleanup under actual live ownership.
Independent review should examine numeric authority loss, known-byte effects,
API ordering and both cookie epilogs before admitting any further composition.
