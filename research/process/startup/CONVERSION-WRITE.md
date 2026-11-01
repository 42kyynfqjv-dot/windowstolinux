# Original narrow conversion writes and program-name publication

## Connected execution

Within the existing explicit native file-mode/UTF-8 launch profile, original
entry now executes the second WideCharToMultiByte call at `0x40b924`, writing
actual converted bytes into the original module-backed buffer. Original
`0x40adc8` stores the byte length excluding NUL. The image-name wrapper loads
that actual length, checks its original cookie at `0x40aea7` and returns through
its original epilog. Caller `0x406727` then stores the program-name pointer,
cleans the three arguments, loads the real command line and initializes the
count-only parser arguments.

The next rejection is **before CALL `0x406755 -> 0x406813`**. The narrow path
bytes and program-name pointer are present; argc/argv globals are still zero.
No argument vector has been allocated or published. This is guarded original
instruction component execution, not whole-PE entry-to-exit translation.

## Bounded write contract

The shared adapter supports explicit CP65001 or CP_ACP=0 resolved through the
existing canonical native UTF-8 process token; it does not infer the Windows
host's ACP. Flags must be 0, default/used-default arguments NULL, input count -1
or positive 1..32767, and the actual converted output must fit a checked owned
writable destination. CP_OEMCP and other profiles remain unbound.

At the write call, the adapter rereads the current owned UTF-16 input. A fresh
read fact covers exactly those units, including the first NUL for count -1.
Positive counts process exactly the selected units and add no NUL. Modern
unpaired surrogates become U+FFFD. The query supplies no copy or destination
authority: a source changed after query is converted from its current value and
rechecked against capacity.

The API checks source lifetime, source/output overlap, call-frame aliases,
destination ownership, complete capacity, permissions and protected/partial
word tags before writes. Numeric output addresses may acquire only a canonical
bounded main-image view; arbitrary stack/heap guesses do not become pointers.
Complete ordinary data-word overwrites discard old authority using the checked
32-bit store. Actual output bytes alone become initialized; tails stay unchanged
or unknown. The source is revalidated before the first write and has no callback
or concurrent guest writer in this supported domain. Earlier completed stores
survive any later rejected effect. The adapter preserves stdcall cleanup and
callee-saved state; successful LastError is unknown, not a fabricated zero.

**Insufficient capacity, strict/error flags, error/errno mapping, capacity growth,
reset/free and exceptional effects remain unbound.** An internal rejection is
not a simulated Windows zero/error return with an unchanged buffer. Windows
observations already demonstrate prefix/replacement writes on failure. No claim
of those failure implementations is made here.

## Independent checks

Seven byte-oracle vectors cover ASCII, Unicode pairs, replacement, positive
embedded NUL, split pairs and -1 termination. Ten storage scenarios cover
insufficient capacity, aliases, unknown/stale input, stale output, partial and
control tags, complete data-word replacement, a changed source after query and
bounds. Six API scenarios check actual write/return, ignored-tail knowledge,
ABI/control aliases, unsupported flags, scalar pointer guesses and insufficient
capacity.

Six Linux original-wrapper scenarios execute actual code with real native
image-name acquisition: module/stack outputs, later cookie failure, changed code,
source/output alias and capacity-growth rejection. The cookie-failure adversary
uses a different declared FILE role only in that independent component fixture,
so an intentional cookie overwrite is not stopped by an unrelated FILE-object
boundary. It does not modify the original PE. Completed conversion bytes survive
that actual original cookie-check failure; no successful return or program-name
publication is supplied. Standalone successful wrappers also cannot publish the
program-name pointer: the actual caller store is independently checked by the
complete entry component.

## Original Windows evidence and remaining uncertainty

Predecessor `568c7ed` passed all three exact-head workflows. Fresh Windows run
**41329013069**, artifact **13092314750**, was independently downloaded: its
15-case API trace matches its stored hash and the predecessor's identical emitted
Rust. The Windows job rebuilt its own authored PE, with a distinct full binary
hash from the local frozen input. [Evidence](evidence/conversion-write.json)
keeps these identities separate; zero new whole-PE pairs are claimed.

The retained Windows trace shows error1113 after replacement bytes and error122
with a written prefix, plus the earlier unsupported flag0x10 return2. Those
failures remain preserved. A separate **158-row Windows capacity matrix** now
records valid BMP/pair/mixed/embedded-NUL and invalid-position inputs, flags0/128,
and capacities around each independently frozen byte count. Failure-buffer bytes
and new strict-invalid outcomes are observations, not guessed atomicity/prefix
rules. Local Rust metadata typechecking alone was not Windows execution;
the fresh CI rows were independently validated below. Unsupported flags remain
excluded.

Fresh implementation-head Windows run **41332040104**, job **124923992596**,
artifact **13094385278** now supplies those 158 rows. The retained
[raw trace](evidence/utf8-capacity-windows-a4c1553.jsonl) hashes to
`94e18f9c7a6f49141d8e9d9d56351df19a5e19c2ca030444388c950ff58a504d`,
matching the workflow report. In this finite matrix, all 98 failed calls with
nonzero capacity wrote the maximum whole-codepoint prefix of the replacement
UTF-8 payload. Strict-invalid queries returned error 1113; short writes observed
error 122 or 1113 according to the case. These observations do not implement or
prove a general error-path contract. The moving `windows-2022` runner is not a
pinned Windows build or XP/7 evidence. [Review and identities](evidence/utf8-capacity-windows-review.json)
keep the Windows rebuilt PE distinct from the local frozen PE.

## Reviewed local verification

Local aggregates passed: **182 root, 333 CRT and 185 unwind Rust tests**;
the two artifact-dependent CRT gates were separately executed by the full
replay. Python suites passed 99 startup tests (one skip), 106 tool tests and
18 corpus tests (one skip). Clippy with warnings denied and formatting passed.

Full replay and fresh repeat emission passed, with identical Rust SHA-256
`851555e8ff75fe3da1c49b52679b890b84b43487bede2e38b34abfed82392536`.
The Windows artifact contains that same emitted Rust. Five retained wrapper
comparisons remain component evidence; zero whole-PE pairs are claimed. Six
original image-wrapper scenarios execute only on Linux, separately from the
Windows API observations and shared native tests. Implementation-head Rust PR
and push CI passed; the inventory workflow's final Linux job was still running
at this evidence snapshot. Later documentation-only heads require their own
CI status.

The next bounded step is original argument counting at `0x406813` and its
classification calls to `0x40b75b`. The downstream storage helper at `0x406985`
calls `0x407cf0` and `0x407d50`; allocation and publication remain separate
gates. The evidence records these original regions' hashes without claiming
they executed.

[Requirements](evidence/conversion-write-expectations.json),
[capacity inputs](evidence/utf8-capacity-expectations.json), and
[verification](evidence/conversion-write.json) distinguish native cases, Windows
API observations and retained wrapper comparisons. Full startup/rcedit/default
admission, XP7 and historical timeout causes remain unresolved. Next close the
original argument counter/parser, allocation and final publication; measured
error-write/growth/cleanup contracts stay separate explicit gates.
