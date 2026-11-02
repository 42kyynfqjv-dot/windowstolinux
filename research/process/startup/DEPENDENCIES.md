# Remaining entry-to-exit dependencies

## Current executable checkpoint: Main entered through the actual startup CALL

The controlled native-profile entry executes CALL 0x401717 into original Main
0x401280, its inline EH4 publication and later saved-SP store, initial locals,
original memset and checked module-root query. Both normal frames and caller
arguments remain live. It stops **before CALL 0x401316 → 0x4011a0**; Outer/Inner,
exception delivery, Main completion and process exit have not executed.

[Staged publication, instruction effects and next scope](MAIN-ENTRY.md).

## Previous executable checkpoint: original Main argument preparation

The controlled native-profile entry executes the original environment getter,
argv/argc cell getters, live loads and ordered pushes. It stops **before Main
CALL 0x401717** with envp/argv/argc on the live guest stack; Main has not run.
The fallback reuses the original checked environment producer. Unknown/stale
payload transport grants no dereference or Main-call authority.

[Producer contracts, failure ordering and next Main scope](STARTUP-ARGUMENTS.md).

## Previous executable checkpoint: original callback-cell getters and NULL decisions

The controlled native-profile entry executes both original getters and reads
both live mapped callback cells. Both NULL branches reach **before CALL0x401700
→0x406c88**, the environment-vector getter. Non-NULL values preserve the original
PUSH/CALL and reject at the unsupported EH4/PE section validator; no callback
value becomes callable authority. Startup state2 and the normal frame remain live.

[Producer provenance, rejection order and next connected scope](CALLBACK-CELLS.md).

## Previous executable checkpoint: original startup release and argument cleanup

The controlled native-profile entry now executes0x4016b4 →0x401a9c and its actual
runtime-flag guard/return, then the original caller POP. Upper argument bits stay
unknown. It stops before **0x4016ba →0x401c2b**, the callback-cell accessor. The
known-scalar XCHG instruction domain is explicit; nonzero-flag TEB/CAS acquisition,
concurrent ownership and unhandled delivery remain unproved.

[Release contract, reviewed evidence and next scope](STARTUP-RELEASE.md).

## Previous executable checkpoint: original C++ initialization and state2 publication

The controlled native-profile entry executes caller result branching, original
void-array traversal, process-owned filter exchange and original new-mode XCHG.
It pops the array arguments, publishes startup state2, pushes the byte-initialized
release flag without inventing upper bits, and stops before **0x4016b4 →0x401a9c**.
The initial previous filter remains unknown; no exceptional delivery is admitted.

[Process-slot contract, review and next release scope](CPP-INITIALIZER.md).

## Previous executable checkpoint: original C-initializer array returned

The final original processor-feature callback now uses the live CPU profile,
stores raw BOOL truth without inventing representation bits, and returns zero.
The original guarded C array completes and restores its saved registers. The
controlled entry reaches **0x401678**, before the caller's argument cleanup,
result branch and C++ initializer array at0x406ca1. Full startup/default/rcedit
admission remains unproved.

[Feature binding, overlap review and next caller scope](FEATURE-INITIALIZER.md).

## Previous executable checkpoint: repeated original locale callback completed

Original0x4109ba now calls the existing guarded locale helper, executes MOVZX/XOR
and returns through the original protected RET. The controlled native-profile
entry reaches **0x4127b0**, whose whole BOOL result store remains unbound. Existing
FILE/environment object and reference-count checks remain intact.

[Locale reuse, CI evidence and next feature-BOOL scope](LOCALE-INITIALIZER.md).

## Previous executable checkpoint: original FILE initialization completed

The explicit controlled native-profile entry executes original FILE allocation,
publication, all three lock constructors, slot stores, descriptor classification
and protected return. It reaches locale callback **0x4109ba**. Canonical FILE
storage and independently owned environment strings remain live.

[Contract, failure ordering and next locale scope](FILE-INITIALIZER.md).

## Previous executable checkpoint: original first-initializer return

The explicit controlled native-profile entry now executes both original
post-environment helper calls, the original TEST and protected RET. Guarded C-array
traversal selects **0x404510**, the FILE initializer whose allocation/lock
composition remains unsupported. Empty and three-entry variants retain published
owned strings after temporary release.

[Review, execution boundary and next FILE scope](POST-ENVIRONMENT.md).

## Previous executable checkpoint: owned environment table and temporary release

The original controlled native-profile entry now reaches **0x4015ee** after
constructing and publishing the empty or nonempty environment vector and freeing
its temporary narrow buffer. Checked original address recomposition preserves
source capability bounds; separate string allocations survive both snapshot and
temporary retirement. Original cleanup executes ordered frees with prior effects
retained on later rejection.

[Contract, evidence and independent Sol review scope](ENVIRONMENT-TABLE.md).
Native resource rejection is not a guest Windows failure observation. Full
startup/rcedit/default admission and historical timeout causes remain unresolved.

## Previous executable checkpoint: original table allocations and precise copy/free gates

Original caller0x406a22 reaches the real table builder. Nonempty input counts,
allocates a distinct zeroed vector and first string, then rejects at original
**SUB ESI,EDI0x4077a8**, whose cross-allocation numeric displacement lacks a
source-authority relation. Empty original entry builds/publishes a NULL-only
vector and rejects at **HeapFree0x407d66** before temporary-buffer retirement.
No nonempty strings/table or full startup completion is claimed.

[Execution evidence and bounded Astra contract](ENVIRONMENT-TABLE.md). Preserve
all prior effects; no integer-to-pointer retag or fabricated free success closes
these gates. Inputs/evidence remain synthetic; broader support stays unproved.

## Previous executable checkpoint: original environment conversion and release

The controlled native-profile path executes both original conversion calls,
original malloc, NULL-free and matching wide-snapshot free. It returns a distinct
initialized narrow buffer through the real epilog. Source aliases expire;
output heap identity remains live. The next boundary is **0x406a22**, before
caller result handling/environment-table construction. No table is published.

[Contracts, review correction and tests](ENVIRONMENT-CONVERSION.md). CP_ACP maps
only through the existing checked65001 profile. No real environment is logged.
Full propagation/startup/rcedit/default admission remain unsupported.

## Previous executable checkpoint: original UTF16 scanner and count

The controlled-launch path executes the original helper at0x40b92f, returns
through CALL0x40b980, then executes its caller's byte difference, word-count
shift and conversion argument preparation. The next exact boundary is
**CALL0x40b996→0x40b8c5**, before the conversion query. Empty blocks take the
original one-word fast path; snapshot layout/lifetime remain checked. No narrow
environment table or original free is claimed.

[Execution, tests and replay-source contract](ENVIRONMENT-SCAN.md). The explicit
profile remains separate from default admission and full startup/rcedit.

## Previous executable checkpoint: owned controlled environment snapshot

Within the deliberately selected controlled-launch environment profile, original
GetEnvironmentStringsW at0x40b96e now returns an independently owned immutable
UTF16 double-NUL block. Original return, pointer move/test and pushes execute.
The next exact boundary is **CALL0x40b980→0x40b92f**, before the UTF16 scan.
The matching success-only free contract has independent ABI/lifetime tests; no
original free call or full environment-table publication is claimed yet.

[Contract, evidence and limits](ENVIRONMENT-SNAPSHOT.md). No host environment is
read or logged. Unicode values/empty entries are supported; non-ASCII names,
hidden drive names, mutation APIs and unmeasured acquisition/free failures reject.
Full startup/rcedit/default admission and historical timeout causes remain open.

## Previous executable checkpoint: boolean return and original environment entry

Original CALL0x4015e0→0x401bd5 executes MOV AL,1; RET with upper-EAX knowledge,
flags and return authority preserved. The original caller TEST/branch enters
CALL0x4015e9→0x406c9c; its original tail JMP0x406a0b observes the initialized
pointer and reuses the original locale initializer. The actual environment
producer prolog at0x40b966 executes, then rejects **before IAT CALL0x40b96e
GetEnvironmentStringsW (0x4150e4)**. No environment block is acquired/published.

[Contract and evidence](BOOLEAN-ENV-ENTRY.md). Next establish owned UTF16
snapshot/acquisition/free and conversion/failure contracts. Full startup/rcedit,
default admission and historical timeout causes remain unresolved.

## Previous executable checkpoint: original thread-locale query

Original mode0 CALL0x4015da→0x407158 runs its actual required-PTD wrapper,
registered/lazy canonical getter, +848 flag read, SETE/INC, return and caller
argument pop. Query results are1 or2; no locale mutation is admitted. Nonquery
modes, unknown decisions, stale UCRT views and required-PTD termination reject.
The next original boundary is **CALL0x4015e0→0x401bd5**.

[Contract and tests](THREAD-LOCALE-QUERY.md). The measured opt-in FP policy remains
separate from unknown/default admission. Full startup/rcedit is unproven.

## Previous executable checkpoint: opt-in initial controls reach post-FP continuation

The measured Win2022 original-entry observation has CW0x027f and MXCSR0x1f80.
A versioned explicit profile now produces exactly those two controls in the
owned guest context. Status, tags and data remain unknown; original FNCLEX
establishes exception knowledge. This is a declared target policy backed by one
modern-host observation, not universal Windows/XP7 state or host inheritance.

Under that profile the original entry executes the FP helper and real return,
then executes the existing original RET0 helper at0x401bbc and PUSH EAX; it rejects at **0x4015da → 0x407158**, the next original configuration-call boundary.
Legacy unknown-state/default admission remains rejected at0x40d013. See
[policy and evidence](FP-INITIAL-PROFILE.md). Full startup/rcedit remains unsupported.

## Previous executable checkpoint: owned FP effects, initial control still unknown

The original precision/query call returns through real instructions in supplied
FP-state component tests, including the MXCSR observation and branch around the
unsupported EH4/DAZ loader. Actual entry now executes FWAIT at0x40d00b and
FNSTCW at0x40d00c; **MOVZX ECX,BX at0x40d013** rejects unknown initial control
knowledge. No known initial FP state is acquired or fabricated. The existing
explicit native profile does not establish Windows loader FP state.

[Contract, evidence and review scope](FP-OWNED-CONTROL.md). Next close original
entry FP provenance, then review partial-knowledge lowering and connected return.
Deferred unmasking, unknown MXCSR, EH4/DAZ and failure termination remain explicit
rejections. Full startup/rcedit/default admission and historical timeout causes
remain unresolved. Zero new whole-PE pairs.

## Previous checkpoint: original FP-control integer prefix


Original CALL0x401be4 ->0x4076a0 now runs validation, branch/argument setup and
actual nested CALL0x40d000. Its real low-level frame prolog executes; rejection
is **before waiting FSTCW0x40d00b**. No FP-state effect, current-control output or
successful return is supplied. Original argc/argv and all prior startup effects
remain. Full/default/rcedit admission stays blocked.

[Contract and bounded Astra scope](FP-ENTRY.md),
[expectations](evidence/fp-entry-expectations.json),
[verification](evidence/fp-entry-prefix.json). Sixteen original boundary cases
preserve partial knowledge, failure ordering, protected returns, output bytes
and pending/unknown guest state. Next establish initial guest FP provenance,
waiting/control effects and the original feature-gated MXCSR path; host FP state
is not a Windows-state substitute. Historical timeouts and prior equivalence
gaps remain unresolved. Zero new whole-PE pairs.

## Previous checkpoint: original post-argv helpers

Original result/stack handling, SLIST initialization, live flag query, conditional
callback encoding and two RET0 helpers execute after actual argc/argv publication.
The FP wrapper pushes its real arguments and rejects **before CALL
0x401be4 -> 0x4076a0**. Its live owned stack is preserved. Private SLIST bytes stay
opaque and old read facts expire; there is no all-zero header assumption or list
operation implementation. Default/full startup/rcedit admission remains blocked.

[Contract/review](POST-ARGV.md), [requirements](evidence/post-argv-expectations.json),
[verification](evidence/post-argv.json). Next inventory and bind the original
FP-control callee only under an explicit guest x87/MXCSR contract, independently
of host floating-point state. Twelve authored Windows PE32 SLIST observations are retained and hash-verified;
synthetic protocol tests remain separate from Windows execution. Resource-failure, freeing/exceptional
cleanup and prior API/profile gaps remain. Historical timeout causes unresolved;
zero new whole-PE pairs. Local 182/337/185 Rust aggregates, Python, Clippy,
formatting, full coherent replay and same-input repeated emission pass. Current
exact-head CI is separate and recorded in the evidence.

## Previous checkpoint: original calloc and argc/argv publication

Original calloc now uses the canonical live process heap, actual zeroing and
owned UCRT errno acquisition. The original NULL-free branch, second parser pass,
argc/argv stores and configuration return execute. Connected entry rejects
**before0x4015a6**, the first C initializer's post-argv continuation. Published
pointers retain the actual allocation identity; no output or allocation outcome
is supplied. This remains an explicit native-profile component, not full startup,
default admission, rcedit or whole-PE translation.

[Contract/review](ARGV-CALLOC.md), [requirements](evidence/argv-calloc-expectations.json),
[verification](evidence/argv-calloc.json). Next bind original post-argv stack/result
handling and actual helper calls, beginning0x4015ac->0x401bc9. Allocation resource
failures, nonnull free/new-handler/wildcard and other existing gates remain
explicit. Historical Windows timeout causes remain unresolved.

Local verification passes 182/335/185 Rust aggregates, 18 new allocation cases,
13 field-view cases and the existing parser cases. Full replay and repeated
emission pass; new exact-head CI remains separate. Zero new whole-PE pairs.

## Previous checkpoint: original argument count and size checks

Original count-only CALL `0x406755 -> 0x406813` now executes the parser and its
live locale classification calls. The caller passes actual counts to original
storage helper `0x406985`, which runs its overflow checks and rejects before
**CALL `0x4069ba -> 0x407cf0`**. Program-name publication remains complete; argc/argv
globals remain zero and no vector is allocated/published. This advances the
original instruction component, not default/full startup or rcedit admission.

[Contract/review](ARGV-COUNT.md), [frozen expectations](evidence/argv-count-expectations.json),
[verification](evidence/argv-count.json). All 53 parser/storage scenarios, 18 SETcc
scenarios, local aggregates and full corrected replay pass. Repeated emission is
identical; new exact-head CI remains separate from these local results.
Next connect the existing original calloc/errno producer under live canonical
heap and exception-registry authority, then the original null-free branch, return and
second parsing/publication. Conversion-error/growth/free/cleanup and broader
profile/equivalence gates remain explicit. Historical Windows timeout causes
remain unresolved; no new whole-PE pairs.

## Previous checkpoint: narrow bytes, cookie return and program-name store

Original entry now completes the fit-domain UTF-8 write, original length store,
image-wrapper cookie check/return and actual program-name pointer store406727.
It cleans the original arguments and prepares count-only parsing, rejecting
**before CALL406755 ->406813**. Narrow bytes and the program-name pointer exist;
argc/argv remain0 and no vector is published. Explicit native mode/encoding and
bounded owned storage are required; no host ACP or unknown byte is guessed.

[Contract/review](CONVERSION-WRITE.md), [requirements](evidence/conversion-write-expectations.json),
[evidence](evidence/conversion-write.json). Independent byte, storage, ABI and
original-wrapper cases cover Unicode/NUL, stale/aliased data, control tags and
writes surviving an actual original cookie failure. Predecessor568c7ed all three
workflows passed; its raw15Windows API rows were checked independently. Fresh
Windows run41332040104 supplies158 retained capacity/error observations, with
raw hash and identical emitted Rust verified. Local aggregates and full replay
passed, including deterministic repeat emission. Implementation Rust PR/push CI
passed; the inventory Linux job was still running at this evidence snapshot.
Failure buffers are not presumed atomic. Strict/insufficient-error/growth/free
and broader admission/equivalence
limits remain explicit. Next execute original argument count/parser and owned
allocation/publication. Fullstartup/rcedit/defaultadmission and historical
Windows timeout causes remain unresolved; zero new whole-PE pairs.

## Previous checkpoint: process file mode and original UTF-8 query

With an additional explicit native process file-mode policy, original entry now
completes the real named lookup/cache/guard/AreFileApisANSI call, locale branch,
conversion body and first WideCharToMultiByte size query. CP_ACP=0 is resolved
through the existing declared UTF-8 process encoding, not the Windows host ACP.
The original write wrapper reaches the second API call at **0x40b924, output
capacity 260**, and rejects conversion write effects. No narrow output or argv is
published. OEM and unverified errors/growth/free remain explicit rejections.

[Contract/review scope](FILE-MODE-QUERY.md), [frozen requirements](evidence/file-mode-expectations.json),
[results](evidence/file-mode-query.json). Shared nonzero symbols preserve BOOL
truth without inventing raw bits; process-owned mode is explicitly chosen.
A demonstrated VirtualProtect reused-stack data-word restriction is fixed with
control/partial/failure checks. Predecessor 4474da6 all three workflows passed;
15 actual Windows API rows are now retained, including failure writes and the
unsupported flag 0x10 result 2. Next close write/source lifetime/alias/error effects
and original stores/cookie return before argv parsing. All earlier admission,
XP7, broader equivalence and timeout limits remain. No whole-PE support claim.

## Previous checkpoint: original locale helper and real named lookup

Original entry executes40ae79/40ab89, existing locale-view constructor40aabe,
code-page read and original file-mode resolver407fc0/407d96/407e41. With actual
module acquisition it reaches **GetProcAddress407efe for AreFileApisANSI** and
rejects the unimplemented named export. Function cache41e000 stays0; no fake
missing-export result, errno127, ANSI default or successful conversion. Prior
startup/onexit/locale/output-record/module-reference effects remain. Original
40ad10 narrow conversion and argv are not yet executed.

[Contract/review/next gate](ARGV-LOCALE-CONVERSION.md),
[expectations](evidence/argv-locale-expectations.json),
[evidence](evidence/argv-locale-conversion.json). Eleven independent native modes
cover original 65001 success and ownership/unknown/cache/mutation rejections.
Six predecessor Windows filename observations are now retained as raw repository
JSONL and hash-validated; 15 new conversion observation cases await Windows CI.
Next close real process file-mode/callable authority and query/copy effects
before executing original conversion/output stores. No assumption of raw TRUE=1
or atomic failure-buffer behavior. Full startup/rcedit/default admission and all
prior cleanup/equivalence limits remain; historical timeout causes unresolved.

## Previous checkpoint: original argument mode and wide image name

Original entry executes `0x401bbf`, argument-config wrapper `0x4069d4` and mode-1
body `0x4066d6`, the original initialized locale check, and image-name wrapper
`0x40ae0d`. An additional explicit native image-name snapshot profile binds
GetModuleFileNameW at `0x40ae32`, writing the real 261-WCHAR checked local buffer.
Original following field initialization executes. The next rejection is **before
CALL `0x40ae79 -> 0x40ab89`**. Narrow output, argv parsing/publication and all
broader startup claims remain unproved; no expected argv or Windows path is
substituted. The previous onexit stores and root frame/state remain intact.

[Contract and review](ARGV-IMAGE-NAME.md), [frozen expectations](evidence/argv-expectations.json),
[evidence](evidence/argv-image-name.json). Next connect actual locale/code-page
and narrow conversion producers, then original argv count/allocation/parsing
with ownership and failure effects. Default admission/full startup/rcedit and
nonempty onexit/growth/invocation remain unsupported. Predecessor `d46b7b6` all
three exact-head workflows passed; historical Windows timeout causes remain
unresolved. Sol can review/continue, escalating only a concrete hard gap.

## Previous checkpoint: original first onexit publication completes

Original memset `0x402370` now initializes the actual 128-byte heap allocation.
Append body `0x4072bb` executes cookie filling, original encoding `0x406d62` and
all four callback/table publication stores. The original manager releases logical
lock 2 and completes checked EH4 cleanup/RET12. Original entry rejects **before
CALL `0x40159b -> 0x401bbf`** in the first C initializer, preserving its root
frame, scope/state and prior effects.
This is explicit-profile mapped native component execution, not whole-PE support.
Nonempty decoding/repeated registration/growth/callback invocation still reject;
scalar encodings never grant pointer ownership.

[Contract and review](ONEXIT-FILL.md), [frozen expectations](evidence/onexit-fill-expectations.json),
[evidence](evidence/onexit-fill.json). Next inspect/execute `0x401bbf` and following call `0x4015a1 -> 0x4069d4`
only where supported; the downstream mode-1 path needs the original
GetModuleFileNameW/narrow-conversion and argument-configuration connection. Persistent encoded-pointer association,
free/resize/exception effects and all earlier broader gates remain unclosed.
Sol can review this slice and inventory the next original call; no automatic
Astra escalation. Predecessor b936882 exact-head three workflows passed.
Historical original-Windows timeout causes remain unresolved.

## Previous checkpoint: original onexit manager reaches real allocation

Original entry now executes401596/401b0f/401ae1, sentinel routing to table41ce88,
actual407525 reference setup, registered EH4 manager407260, logical lock2 and
append-prefix decoding/growth. First NULL recalloc reaches original malloc and
allocates128 unknown bytes from the canonical heap. It rejects **before original
memset CALL40c8ae ->402370**, preserving the active frame/lock, callback argument,
unchanged encoded table and prior startup/x87 effects. No callback is published.
The default/unconfigured x87 domain still rejects earlier; no whole-PE support.

[Contract/review scope](ONEXIT-REGISTRATION.md),
[frozen expectations](evidence/onexit-expectations.json),
[evidence](evidence/onexit-registration.json). Next close actual memset effects
and producer-bound encoded allocation/callback publication, then resize/lifetime
and normal cleanup. A real live-buffer encoding test currently rejects without
such authority; do not promote decoded numbers into pointers. Sol review first;
bounded Astra High for this concrete ownership integration if useful, no Ultra.
Predecessor dcf7882 had a preserved original-Windows case5timeout; its other two
workflows passed. That and all historical timeout causes remain unresolved.

## Previous checkpoint: explicit x87 effect and empty preinitializer return

With the additional declared modern-enabled stationary x87 profile, original
entry executes FNCLEX40158a with actual guest status effects and unknown C0..C3,
then the original equal-bound empty helper401e00 and actual PUSH401591. It rejects
**before CALL401596 ->401b0f**, preserving the callback argument401e2c, scope0,
state1, caller frames and prior effects. Unconfigured/default domains still stop
before FNCLEX. Guest x87 state is not host FPU state or a Windows capture.

[Contract/review scope](X87-STARTUP.md), [frozen expectations](evidence/x87-expectations.json),
[evidence](evidence/x87-startup.json). Next connect original onexit registration
401b0f/401ae1 and encoded callback ownership/failure effects, without executing
or skipping registration as a stub. Sol review/inventory first; no automatic
escalation. All other floating instructions, full startup/formatter/rcedit,
default admission and broader equivalence remain unsupported. Native42 Linux
instruction observations are not Windows/whole-PE comparisons. Historical
original-Windows timeout causes remain unresolved.

## Previous checkpoint: guarded C-array enters original setup callback

Explicit-profile original entry executes CALL401673/406ccc, skips the null,
validates the real guard and runs the first callback40155a through app/filemode/
commode and distinct onexit-sentinel initialization. It rejects **before x87
FNCLEX40158a**; no x87 environment is modeled. Scope0/state1, array arguments,
caller frames and prior effects remain live. Other five callbacks are fully
inventoried; two supported bodies execute only in separately declared arrays,
and FILE/locale/raw-BOOL consumers remain explicitly rejected. No later callback
is skipped or assumed successful in actual entry order.

[Contract/inventory/review scope](C-INITIALIZERS.md),
[frozen expectations](evidence/c-initializer-expectations.json),
[evidence](evidence/c-initializers.json). Next gate is coherent shared x87
state/environment semantics and remaining first-callback instructions, requiring
a bounded deeper design pass rather than erasing FNCLEX. Sol review/CI can run
first. Default admission, full startup/formatter/rcedit, cleanup/delivery and
broader equivalence remain unsupported; zero new whole-PE pairs. Historical
original-Windows timeout causes remain unresolved.

## Previous checkpoint: caller activates scope and reaches C-array initializer

Explicit-profile original entry now executes POP401632, AL branch, BL/local
writes, scope-2 ->0, real CALL401647/401913 and its live flag getter4021bf. The
unchanged input takes the checked zero-flag return. Caller writes startup state
41cc7c=1 and pushes actual C-array bounds41513c/415158, then rejects **before
CALL401673 ->406ccc**. Argument words, active scope, frame and prior effects
remain; no cleanup or whole-startup completion is fabricated. Nonzero guard flag
rejects before FS:[18]/CMPXCHG; unknown/failure/reentry branches remain explicit.
[Contract/review scope](STARTUP-CALLER.md), [evidence](evidence/startup-caller.json).

Next: shared guarded C/C++ initializer-array traversal and actual callback/error
effects. The C array is not empty: NULL plus40155a,401605,404510,4109ba,40c109,
4127b0. The subsequent C++ array has NULL and40160d. Preserve state1/scope0 and
failure effects; do not skip unbound targets. Sol can start the bounded inventory
and traversal. Escalate only a demonstrated hard semantic/ownership gap; no Ultra.
All broader default admission/startup/formatter/rcedit and cleanup/delivery,
resource/encoding/XP7 equivalence gaps remain unsupported. Historical original
Windows timeout causes remain unresolved; exact-head CI is tracked in SUB-579.

## Previous checkpoint: initializer table completes; startup prefix remains open

Explicit-profile unchanged entry now runs callback15 at407565 and both original
exit-table helpers4074fc, initializes separate tables41ce88/41ce94, completes the
initializer loop and returns to **401632**. It explicitly rejects before that
original POP ECX. The argument and outer EH4 frame remain live; no full startup
return or ordinary conversion is claimed. The paired401bd5 cleanup is the actual
AL=1/RET no-op, not table draining/freeing. Prior stores survive later rejection.
[Contract and review scope](EXIT-TABLES.md), [evidence](evidence/exit-tables.json).

Next lift the caller's POP/TEST/branches and scope activation, then CALL401647 to
401913. That helper first reads live41d2f0 via4021bf; its nonzero path needs owned
FS:[18]/StackBase and CMPXCHG. Do not assume a flag value or expand authority.
Sol can handle the bounded caller/flag path; justify any deeper thread/atomic
ownership design before escalation. Existing default admission/full startup,
formatter/rcedit, non-null freeing, exceptional delivery/cleanup and all broader
resource/encoding/XP7 equivalence gaps remain unsupported. Historical original
Windows timeout causes are unresolved; exact-head CI is tracked in SUB-579.

## Previous checkpoint: shared locale updater returns

Explicit-profile original entry now completes callback10: real EH4 wrapper40aeae,
lock5, checked257/256-byte copies, global/private reference replacement, unlock,
RET12 and outer initialized-flag publication. Copy paths execute original scalar,
REP or nonfaulting aligned SSE2 instructions; unproved SSSE3/backward/unaligned
paths reject. Canonical mapped byte destinations cannot alias a stack frame.
Prior writes survive later rejection; replay cannot repeat publication.

Next actual initializer boundary is **index15, target407565**, calling4074fc twice
with 41ce88/41ce94. Index14 reuses its already-bound original helper. The original
three-word exit-table cookie initialization and return must execute before
advancing. Non-null free,
invalid-argument/errno, exceptional cleanup and other gaps below stay unsupported.
[Contract and review scope](LOCALE-SHARED.md), [evidence](evidence/locale-shared.json).
All three dfb3d77 workflows passed. New-head CI remains separately reported in
SUB-579. No new whole-PE pair, default admission or full startup/rcedit claim;
historical original-Windows timeout causes remain unresolved.

## Previous checkpoint: PTD reference publication reaches shared EH4 update

Explicit-profile entry now executes original result caller40b2cc, old-reference
decrement, new counter1 and pointer publication to UCRT PTD+72. It rejects at
**CALL40b362 ->40aeae**, with these effects retained and initialized flag41d148
still0. A declared per-thread-mask component separately executes real null-free
and aligned return; original entry data is not tuned to take that branch.
The caller continuation is single-use, and unknown byte/pointer knowledge stays
bounded. Non-null free, error errno and exceptional cleanup remain explicit gaps.

Correction:407126 is a scalar flag XCHG, not a lock acquisition. Real indexed
lock5 belongs to the next shared EH4 updater. Next connect its original8-byte
local allocation, copy/reference body, owned lock cleanup and RET12 using existing shared
machinery. [Contract, evidence and review scope](LOCALE-RESULT.md).
All c0d42a7 workflows passed; earlier original-Windows timeout causes remain
unresolved. No new whole-PE pair, full startup/rcedit or default admission.

## Previous checkpoint: original UTF-8 initializer returns

Under separate explicit ACP65001 and installed-code-page profiles, original
IsValidCodePage40b4e6 now executes a measured bounded API contract. Original UTF8
stores/classifier40b090 loops and both cookie checks/returns execute on canonical
owned storage. Caller rejects at **0x40b2cc**, before result/reference/publication
or cleanup. Unknown bytes stay unknown; changed code/IAT/ownership rejects with
earlier effects preserved. No new whole-PE Windows/ELF pair or default admission.
[Scope, raw Windows results and review gates](LOCALE-UTF8.md).

Next execute the original result handling, reference replacement/publication and
cleanup. Other code pages/NLS, freeing, exceptional cleanup and the broader gaps
below remain unsupported. ACP1252 on the separate Windows observer is not target
ACP evidence. Interim9664382 PR CI's original imported hello timeout remains
unresolved separately from previous launches; push/startup CI at that head passed.

## Previous checkpoint: original initializer reaches validation API

Under the explicit65001 profile, original CALL40b2c7 and initializer40b485 execute
cookie/frame setup, the existing selector and five-entry table search. Execution
now rejects at **IsValidCodePage CALL40b4e6/IAT4150cc**, before an API result.
The caller bytes are checked before activation, and complete original initializer
bytes before its prolog. Its real selector clears41d144; this prior write and live
stack/cookie/argument state remain. The544-byte copied buffer has no new semantic
role or published reference. Actual entry flag41d148 stays0; old references remain.
[Contract, test scope and frozen conformance](LOCALE-VALIDATION.md).

Shared CRT word-register loads/extensions retain knowledge/flags and reject forged
pointer authority; normalized decoding is not proof of alternate API/helper paths.
Dedicated REP behavior remains independently checked, including later page-write
failure and retained progress. [Preserved copy contract](LOCALE-REP.md).

Next: measure/bind supported IsValidCodePage behavior without inventing invalid
results for unsupported encodings, execute original UTF8 fields and helper40b090
loops/cookie epilogs, then original result/reference/publication/cleanup. Other
code pages/GetCPInfo/NLS, freeing and exceptional cleanup remain unbound. Target
Windows ACP still needs matched-environment evidence; explicit-profile success or
a separate observer's ACP is not default whole-PE support.

At6daf5ad, both Rust CI runs failed different original-Windows launches; other8jobs
in each and all13startup jobs passed. Both originals had expected output but were
still alive at15s. Cause unresolved, separate from historical case19. A fixed
nine-sample exact-image/context experiment preserves every failure and the same
limits. [Evidence and diagnosis](WINDOWS-LAUNCH-6DAF5AD.md).

At 0f6a9c3, both exact-image launch matrices and original comparison gates passed;
the new Windows API probe measured 65001 valid, UINT_MAX invalid and ACP 1252.
These do not establish target ACP or diagnose historical hangs. Startup inventory
failed a generated word-test child's main-stack layout, with three dependent jobs
skipped. The test-only repair retains all 152 cases in separate non-inlined frames,
passes a lowered 512 KiB Linux child limit, and preserves identical emitted runtime
Rust. Fresh fixed-head Windows CI is required. [Repair evidence](evidence/word-register-stack.json).

## Previous checkpoint: original comparison and malloc

Original malloc returns a fresh544-byte flags0 Buffer with unknown contents.
Flags8 alone zeroes; no semantic PTD/descriptor/locale role follows from success.
Actual heap identity/ABI and resource checks remain. Original errno/new-handler
paths reject with prior effects retained. [Preserved contract](LOCALE-MALLOC.md).

## Previous checkpoint: original code-page selector

The original -3/GetACP branch returns65001 from the same live token as A/W command
line data. Missing/stale profile, OEM and per-thread mutation effects reject with
prior writes retained. [Preserved selector contract](LOCALE-CODE-PAGE.md).

## Previous checkpoint: original multibyte reference helper

The registered helper40b38a executes its original reads, reference operations,
lock5 cleanup and normal epilog. The earlier 1a08b95 checkpoint stopped at40b25f;
its completed replay retained five recorded wrapper component comparisons.
[Preserved helper contract](LOCALE-REFERENCE.md).

## Earlier checkpoint: aligned activation



The explicit UTF-8 native launch (process code page65001) now captures real Linux
argv once and constructs a canonical MSVC command line. It does not recover an
original Windows raw command line or guess a legacy ACP. A/W buffers are separately
initialized, read-only, process-owned mappings with stable pointers and transactional
pair publication. Invalid native UTF-8, unsupported argv0 and length/code-page
inputs reject; Unicode and quoting are preserved within the declared profile.

Original callback9 at0x407093 calls the actual bound GetCommandLineA/W producers,
stores pointers to0x41ce74/0x41ce78, sets AL1 and returns. A later W/import/return
failure preserves an already completed A store. API calls invalidate unproved
LastError knowledge. All earlier endpoint, UCRT and descriptor state remains.

The explicit native entry now executes callback10's three original locale-pointer
stores and required-PTD getter `0x40a2ef`, preserving the same 868-byte UCRT heap
identity and retiring the getter's temporary C++ record. The actual CALL enters
`0x40b235`, preserves stack authority through alignment, stores non-authoritative
return-address bits in the compiler mirror, allocates the local frame, and pushes
the first body's arguments. It rejects **before CALL `0x40b25a -> 0x40b38a`**.
The locale initialized flag remains zero. This is connected component replay,
not full startup, rcedit or default admission.

[Shared aligned activation and exact next helper](LOCALE-STARTUP.md). The next
executable dependency is `0x40b38a`: an original EH4/lock5-protected UCRT multibyte
reference getter/replacement with decrement/free, publication, increment and
cleanup effects. Existing reference/registry machinery should be reused; the
inventoried LOCK XADD at0x40b3d8 additionally needs shared old-value/flag effects
and is not yet supported by CRT IR. This body remains unexecuted. Its
termination path and later GetACP/GetCPInfo remain unimplemented; no universal
UTF-8 ACP premise or successful body callback is introduced. Aligned-frame
nonlocal cleanup is still unsupported, independently of tested normal epilog.

## Earlier checkpoint: actual native standard endpoints and callback8 return

The optional native launch profile now acquires real Linux stdin/stdout/stderr as
owned resources before entry. Process handle authority is separate from CRT
numbers/locks. The unchanged 0x4085e7 body retrieves and queries those endpoints,
performs its original classifications/stores, and returns. Callback8 executes its
original cleanup and epilog; the outer lock7 lease retires and all prior UCRT,
descriptor block/capacity64 and record-object state remains canonical.

Entry next rejects at **CALL 0x40c946 -> 0x407093, table index9**, before that
callback executes. Its 25 unchanged bytes call GetCommandLineA (IAT0x41508c), store
to0x41ce74, call GetCommandLineW (IAT0x415090), store to0x41ce78, then return AL=1.
Neither string producer has been acquired. The next coherent gate is process-owned
narrow/wide command-line storage, explicit native argument/encoding policy and
original publication. Linux argv is not a recovered Windows raw command line.

[Native producer, partial effects, close/EOF limits and conformance](NATIVE-STANDARD-HANDLES.md).
This is Linux original-instruction component execution under a declared native
launch policy, not a new Windows startup observation or whole-PE pair. Other hosts
still stop before the standard initializer; default/full startup/rcedit/XP7 remain
unsupported. Existing metadata and nonempty-inheritance limits remain.
Earlier checkpoints below are historical.

## Earlier checkpoint: native launch metadata and shared handle lifetime

The optional `w2l-native-startup-metadata-v1` extension defines a native launch
without a Windows CRT serialized inheritance block. Under this additional explicit
policy, the unchanged `0x408537` body executes GetStartupInfoW and its actual
empty-inheritance branch, returns, and reaches **CALL `0x4086c3 -> 0x4085e7`**
(the standard-handle initializer). That call still rejects before execution.
The former second-fiber profile without this extension still stops at GetStartupInfoW.

The 68-byte output has a known `cb`, zero `cbReserved2` and null `lpReserved2`;
all other fields stay unknown. This is declared native launch metadata, not an
acquisition or observation of a Windows parent's startup records. Nonempty CRT
inheritance and actual standard handles remain unproduced. Descriptor identities
now permit a shared handle and propagate successful or unobserved close effects
to all aliases; numeric reuse cannot restore old authority.

[Contract, independent regressions and exact next producer scope](STARTUP-METADATA.md).
No new Windows observation/ELF pair, default admission or full startup/rcedit claim.
Earlier checkpoints below are historical.

## Earlier checkpoint: original descriptor manager and 64 record locks

Callback8 now executes its EH4 prolog/lock7 and original nested manager/constructor.
Original calloc(64,56), 64 native record initializations, original field stores,
block/capacity publication, manager cleanup and original epilog run on the same
canonical process heap and live epoch. The 868-byte UCRT allocation stays distinct.

Entry next rejects at **CALL `0x408543`, GetStartupInfoW, inside original `0x408537`**.
Capacity64/block publication and all record objects remain; the nested lease is
released while callback8 retains its outer lease and frame. Startup-info output,
inherited/standard-handle acquisition, callback completion and rollback are unproved.
[Contract, failure ordering and next producer gate](STARTUP-DESCRIPTORS.md).
No new Windows/ELF pair, default admission or full startup/rcedit claim.
Earlier checkpoints below are historical.

## Earlier checkpoint: locale publication and original UCRT return

Original helper `0x40a00d`, replacement, module reference walker, guarded static
child, cleanup and RET12 now execute under the live startup registry. The original
null-free branch and LastError restoration execute; the original getter returns
and its C++ record retires. Callback7 completes, leaving the same868-byte allocation
published to the current fiber and both helper leases released.

The next boundary is **indirect CALL `0x40c946 -> 0x408697`, callback8**. Its lock7
EH4/descriptor/standard-handle initialization remains unbound. Reuse existing
manager/standard-handle components with the actual producer state and epoch.
[Contract, partial effects, limits and next integration gate](UCRT-LOCALE-PUBLICATION.md).
Dynamic prior-reference release, XADD, nonnull free and exceptional containment
remain rejected. Default/full startup/rcedit are unproved; no new Windows/ELF pair.
Earlier checkpoints below are historical.

## Earlier checkpoint: first locale reference and normal EH4 cleanup

The explicit-profile original entry now executes helper `0x409efb`, including its
live nested EH4 record, actual indexed acquisition, checked module-word LOCK INC,
original cleanup release and proved original epilog/RET 12. The reference update
survives later rejection. The first helper's record/lease retire on normal return.
Execution now rejects at **CALL `0x40a0f9 -> 0x40a00d`**, before the second locale
publication helper. The getter record and published UCRT allocation remain live.

[Contract, failure ordering and next connected gate](UCRT-LOCALE-REFERENCE.md).
The next gate is the original lock-4 EH4 publication/replacement and child-reference
walk, followed by destructor/failure closure. Exceptions within the first helper,
general concurrent atomics, XADD and full startup remain unsupported. No new
Windows/ELF pair or default/rcedit admission. Earlier checkpoints are historical.

## Earlier checkpoint: owned UCRT allocation and initializer prefix

Original entry under the explicit second-fiber profile now executes lazy sentinel
publication, original calloc(1, 868), checked native heap allocation and publication
of the same allocation to the current fiber. The original initializer's scalar and
word writes execute. It rejects at **CALL `0x40a0d0 -> 0x409efb`**, before locale
reference acquisition; the published object, prior writes and getter registry
record remain live. The 40-byte VCRUNTIME view stays distinct and cannot accept it.

[Contract, evidence and connected locale/cleanup gate](UCRT-ALLOCATION.md).
Native allocation/resource rejection is not a proven Windows allocation-failure
result. Original retry/errno, failed publication, locale helpers, ordered destructor
and normal return remain open. Default/full startup/rcedit remain unsupported;
no new Windows/ELF pair. The following checkpoints are historical.

## Earlier checkpoint: registered UCRT getter and native FLS read

The explicit second-fiber profile now carries the actual live `NormalCallEpoch`
from original entry through initializer/table/callback7 into UCRT getter
`0x40a332`. Its original prolog links the byte-backed C++-style record to the same
canonical startup chain. Actual GetLastError and the original static FlsGetValue
thunk execute; the newly allocated native index1 issues its current stationary
fiber's documented initial null value, without a supplied slot or PTD pointer.

Execution now rejects at original CALL `0x40a3a3 -> 0x40a1ee`, before lazy PTD
allocation. The live record and prior cache/FLS/lock effects remain; callback7
has not completed and no PTD heap object or restoration receipt is issued.
[Contract, independent cases and exact next gates](STARTUP-PTD-ACQUISITION.md).

The next UCRT body requires sentinel publication, calloc(1,0x364), failure cleanup
and original initializer40a067 (including409efb/40a00d locale/reference helpers).
This868-byte object is distinct from the existing40-byte VCRUNTIME dispatcher
PTD view; do not retag/copy that view or assume locale initialization. Reuse checked
heap, FLS setter and shared registry transitions with a justified UCRT object view.
Default admission/full startup/rcedit remain unproved; no new Windows/ELF pair.
Earlier checkpoints below are historical and superseded where stated.

## Earlier checkpoint: protected second-resolver publication

Under the explicitly enabled `w2l-native-second-fiber-20348-2398cc6a-v1`
extension, unchanged entry now executes indexed lock CALL `0x407e92 -> 0x40bdcf`,
original VirtualProtect RW, cache XCHG `0x407ec8`, RO restoration and matching
release `0x407ede -> 0x40be17`. Logical lock14 resolves by its checked address to
owned slot15 in this entry; independent permuted storage resolves it to slot5.
No slot number is substituted into guest registers or original address arithmetic.

The selector returns, its original flag store executes, and the original allocation
wrapper allocates **second process FLS index1**, callback `0x40a100`, publishing
index1 to `0x41c170`. The earlier index0/value remain intact. The exact next stop
is CALL `0x40a428 -> 0x40a332`, registered PTD acquisition context unbound, before
producing its PTD or completing callback7. `0x41e00c` is the original missing-export
sentinel `0xffffffff`, its page is read-only, and the cache lock is released.

[Contract, failure ordering and independent cases](CACHE-PUBLICATION.md).
Default admission still rejects `0x402b00`; no new Windows/ELF or whole-PE pair.
Next connect the actual registered PTD getter using the live startup registry and
existing lazy producer, retaining process-slot/fiber-value/allocation identities.
Sol can review and attempt this connection; escalate only a reproduced ownership
or continuation ambiguity. Older checkpoints below retain historical evidence.

Current checkpoint: explicit extension `w2l-native-second-fiber-20348-2398cc6a-v1`
uses verified x86 KernelBase identity and missing FlsGetValue2/error127. Unchanged
entry publishes the owned module and executes lookup, then rejects indexed lock
CALL `0x407e92 -> 0x40bdcf`. No second index, feature-flag result or function-cache
publication is claimed. Older profile/default admission remain blocked.
[Versioned contract, Windows provenance and tests](SECOND-FLS-PROFILE.md).

Current checkpoint: original callback `0x40a407`, selector and second resolver
execute to `LoadLibraryExW` at `0x407f1d`, first candidate
`api-ms-win-core-fibers-l1-1-2` while resolving `FlsGetValue2`. The explicit native
profile rejects that unproved mapping. Unchanged entry has not allocated its
second FLS index. Seeded cache conformance cases reach actual native allocation
and then reject the registered PTD context boundary.
[Original execution, independent tests and remaining integrated gate](SECOND-FLS-INITIALIZER.md).
Default admission/full startup/rcedit remain unproved.

Current checkpoint: original process-heap callback `0x40c8f0` publishes the same
canonical Space-owned heap proof to `0x41d2c8` and returns AL1. Its original
cleanup clears that cell without destroying the heap. Entry next selects index7
/ `0x40a407`, whose body remains unbound. Allocation policy stays unknown unless
independently established. [Identity, ordering and cleanup](HEAP-INITIALIZER.md).
Default admission/full startup/rcedit remain unproved.

Current checkpoint: original callback `0x401bd5`, the fifteen-record lock loop
`0x40bd8e`, its original tail thunk and checked native synchronization execute.
The next selected callback is `0x40c8f0` (GetProcessHeap via IAT `0x4150f8`),
whose body remains unbound. Count 15 and all locks remain live at rejection.
[Original execution, rollback tests and CI harness repair](LOCK-INITIALIZERS.md).
Default admission/full startup/rcedit remain unproved.

Current checkpoint: the explicit native profile executes original callback
`0x408113`, its `VirtualProtect` call at `0x408129`, original zero/nonzero result
handling and protected return. `.fptable` becomes read-only with canonical mapping
identity; old protection is written to the original stack local. Prior callback,
FLS and lock effects survive. The original loop next selects index 3 / `0x401bd5`
and rejects its unbound body. See [page contract and exact next scope](VIRTUAL-PROTECT.md).
Default admission, full startup/rcedit and Windows failure equivalence remain open.
The checkpoints below retain earlier evidence and are superseded where stated.


Current checkpoint: original16-entry initialization/rollback loop executes with
index/phase/owner-bound callback receipts. Two original callbacks and all five
scalar-store callees execute; the third reaches VirtualProtect408129 with checked
original arguments. No permission/output effect is admitted. Prior FLS, lock and
callback writes remain live. Default admission is unchanged. See
[ordering, negative tests and page-permission architecture gate](INITIALIZER-TABLE.md).

Current checkpoint: original FLS setter/resolver/guard/indirect stdcall8 executes.
The explicit native FLS service publishes opaque41ccc4 for the current stationary
fiber and retains its real process-index/callback identity. Retrieving the value
grants no pointer/PTD authority. Original module initialization returns; the next
explicit boundary is startup initializer continuation40195f, with next inventoried
CALL401967 ->407653. Default admission is unchanged. See
[setter contract, recovery and regression evidence](FLS-SETTER.md).

Current executable checkpoint: with an explicitly enabled native FLS service,
original allocation wrapper/resolver/guard/indirect call and index store execute.
Entry allocates a process index and retains callback ownership, then executes the existing original RET0 helper at0x401bbc and PUSH EAX; it rejects at
setter `0x402981 -> 0x402bef` before publishing a fiber value. Default admission
remains blocked. [Contract, reproduced stack regression and next gate](FLS-ALLOCATION-WRAPPER.md).
Earlier boundaries below are historical.

Latest follow-up: a real bounded native FLS process-index producer and checked
stdcall adapter now exist, with no supplied allocation outcome. Original entry
executes the FLS initializer through CALL `0x402968 -> 0x402b3e`; its allocation
wrapper/export binding still rejects, so entry has allocated/published no FLS
index. Prior lock/count effects remain. Default admission is unchanged. See
[producer, tests and exact wrapper connection](NATIVE-FLS-PRODUCER.md).

## Earlier checkpoint: native-profile lock construction

The explicit native profile executes the original guard, indirect synchronization
call, constructor RET and lock-count publication. The mapped lock remains live
with count1 when original FLS acquisition `0x4024d6 -> 0x402963` rejects. Default
admission remains blocked at `0x402b00`. Native fixed storage and checked ABI are
implemented; arbitrary Windows resource-failure correspondence is still unproved.
This is component execution, not whole-PE support. See
[contract, review defect and next scope](PROFILE-SYNC-CALL.md).

The entries below retain earlier checkpoints and remaining independent paths;
older exact stopping addresses are historical, superseded by this checkpoint.

Target: the retained, unchanged authored MSVC `unwind.exe` used by
[ENTRY-TO-EXIT.md](ENTRY-TO-EXIT.md), PE SHA256
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`.
This map records connected instruction paths and their supplied contracts.
It is not whole-image conversion evidence. rcedit remains a later independent gate.

| Path | Executed original instructions | Remaining supplied contract / next gate |
| --- | --- | --- |
| Entry and module/thread startup | Selected initialization components | Actual header-entry composition, loader effects, incoming thread/handler chain, module and FLS producers |
| Main, RaiseException, delivery | Main/handler/restore slices and owned activation machinery | Original delivery/context acquisition and incoming-chain containment; no replacement of saved exception context by call registers |
| Normal C++ handler | Prefix414ad6, common403002, thunk403e78, dispatcher403d76, checked context/guard, dynamic PTD/FLS getter and normal epilog form one component path | Bound module/function, live fiber/index/slot and captured delivery inputs. Normal return is ContinueSearch1, not resumed guest execution |
| C++ unwind | Wrapper4041a4/body4041bc register their original EH4 frame, execute state helpers, counter and traversal, and retire normally for state-1; pending actions reach original bridge/notification writes | Original cached PTD getter/FLS is connected; module/export/fiber/slot acquisition remain supplied. A scoped child grant now supports the original body during a pending component exception without unsuspending its parent. Original common dispatcher call403de2 is connected under child authority; original prefix414ad6 is connected under the same child authority; a same-event invocation/receipt now binds supplied captured objects through result consumption; actual Windows delivery/registration selection and exceptional funclets remain unbound; action4026fc reaches unbound terminate40770c. See [component contract](CXX-UNWIND.md) |
| Required-PTD / terminate / abort | Static targets and original normal getter null/sentinel branches are bound | Required-PTD null reaches4077ff. This needs signal query40cbcf/40cafd, lock/EH4 effects, encoded signal callback, flags41c128, signal22, fast-fail/debug and exit effects; never substitute successful cleanup |
| printf and output | Wrapper/accessors, owned FILE/lock, low-I/O and writer components | Actual locale/FILE initialization, complete formatter driver/parser/destruction, callback/exception paths and physical stream composition |
| Return and exit | Main report/epilog and shutdown components | Original exit registrations, flush/close/error/status and process termination from the same live entry state |

## Current acceptance evidence

The common-handler path removes its synthetic PTD backend callback: fixed Cached
access reaches the actual getter and checked FLS slot without an initialization
lease or loader callback. Twenty native cases exercise normal dispositions and
ownership/failure rejection. The retained Windows wrapper comparisons remain
component boundaries. New state helpers add twelve native cases (eight owned
read/write cases and four independent signed-byte/full-word boundaries), with no
new original-Windows observations or whole-PE pairs.

State404406 is written *before* the action in the original loop. A next-state
write is not proof that its action ran. The adapter returns the original register
result only and issues no cleanup, dispatch, restoration or shutdown receipt.
The loop controller must retain the pending old index/action/owner across that
write, then consume it only after justified callback execution or terminal effect.
The current unwind path remains rejected; reading state-1 after a manual helper
step cannot authorize resumption.

## Next cohesive implementation gate

The registered unwind component now has24 independent native scenarios and
original bridge/notification writes. It preserves pending action ownership across
the pre-action state write and rejects at terminate40770c. Empty-state returns
balance the counter and retire the original frame. No cleanup receipt follows
an unexecuted action. Details and supplied-state limits are in
[CXX-UNWIND.md](CXX-UNWIND.md).

The original cached PTD getter is connected with14 native cases. A separate
scoped delivery-child grant now supports its registered body while the interrupted
frame remains suspended (14 ownership cases and four connected original-body
cases). No nested exception or restoration is authorized by child completion.
The actual common dispatcher call403de2 → wrapper4041a4 is connected with eight
additional native cases. The original handler prefix now carries the same child
authority through guard and metadata production (14 more native cases). The
component supplies Windows delivery/registration selection and captured state.
The supplied invocation is now bound to the same pending event and owner, with
full object bounds and lease-bound result consumption (30 native cases).
Close terminate40770c's PTD+12 callback/guard and abort4077ff signal/lock/exit
effects; retain rejection for exceptional funclets until their delivery and
cleanup are justified. Actual delivery acquisition and incoming-chain containment
remain separate gates. This is not whole-PE translation evidence.

The legacy split-head boundary remains reproduced in [THREAD-CHAIN.md](THREAD-CHAIN.md).
The new registered original PTD helper shares the canonical EH4 head, typed
predecessors, full frame bounds and child-lease lifetime. Twenty-four native cases
cover mixed and directly nested registrations, stale/replayed authority, failed
writes and pending delivery. Shared-head success does not derive a selected
handler: existing result receipts identify the interrupted event but not the
executing chain node. Next, bind original handler execution and disposition to
that node before any single-use cursor advance. Keep actual capture/flags,
C++ source activation, borrowed-chain containment and collided delivery explicit.
No whole-image conversion or new Windows observation is claimed.

## Objective whole-program acceptance

One normal converter invocation on the unchanged PE, from its header entry,
must produce deterministic Rust/ELF with no supplied state/result vectors or
skipped startup. Require matching original Windows and Linux stdout, stderr and
exit, artifact/source/toolchain hashes, failure-path checks, and independent
lifetime/alias/unknown-state/cleanup negatives. Passing individual rows does not
establish their entry-to-exit composition.

## CI evidence

The reviewed predecessor `8efaffc` completed all three workflows successfully:
Rust PR40965890530, Rust push40965882528 and pinned startup40965882457.
The earlier `f5cbd05` also completed all three successfully:
40964376142, 40964368746 and 40964368751. These are predecessor results;
new shared-head changes require their own final-head checks.

At the preceding checkpoint, fe0d0dc push run40949077644 attempt1 failed artifact
creation with ECONNRESET, leaving later comparisons skipped. Its exact job/steps
remain in [upload-reset-fe0d0dc.json](evidence/upload-reset-fe0d0dc.json).
Only failed job123714769651 was explicitly retried through GitHub's normal API;
Run attempt2 completed successfully, including rerun Linux job123720191590. This is a labeled infrastructure retry of the *old* commit. It neither
erases attempt1 nor validates newer heads. Historical original-Windows process
exit timeouts remain separate and unexplained.

The executed C++ component receipt now retains proved handler/metadata/dispatch
identity and live owner/frame through single-use consumption (34 invocation
cases). Ordered advancement remains blocked at the earlier EH4 source: the
original empty-scope Search proof returns ContinueSearch, but the native search
emitter requires a GlobalUnwind action. THREAD-CHAIN.md records the exact
reproducer and return-path integration, with no supplied success receipt.

Independent Sol review of214d585 additionally confirmed that generic proved-path
lowering requires a terminal CALL and explicitly rejects RET. The owned-search
CALL cut uses a different storage/lifetime authority from pending normal delivery.
Return-only support therefore needs a verified terminal RET contract and live
normal-frame adapter together, preserving the interrupted source's suspension;
removing the GlobalUnwind check alone is insufficient. See THREAD-CHAIN.md.

## Current return/advance integration

The earlier return-only emitter gate is now implemented as a separate RET
contract and live pending-event adapter. The original EH4 empty-scope search runs
its prefix/helpers/epilog and produces an actual ContinueSearch result. A receipt
bound to that normal registration permits exactly one checked advance to the
predecessor; source suspension and physical thread head remain intact. Twenty-one
cursor cases plus a standalone native return case cover execution and rejection.
See [THREAD-CHAIN.md](THREAD-CHAIN.md) for contracts and limitations.

Next connected gate: invoke the selected C++ registration with its own live owner
and the same search event. The current C++ component invocation accepts a supplied
owner and unwind flags; it must not be relabeled a search-selection certificate.
Actual captured-state acquisition, loader/FLS producers, incoming/collided
semantics and termination stay separate unresolved prerequisites. New evidence
is component execution from retained original bytes, not whole-PE translation.

Validation for the return/advance checkpoint: 223 CRT tests passed (one retained
observation test run separately), 175 root tests passed, and all-target Clippy
passed with warnings denied. The retained-artifact checker passed, including five
recorded Windows wrapper comparisons and all new native cases. It retained PE
SHA256 `1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`
and generated harness SHA256
`fe270f49ba9a37241c585bafbc6d6c837e01696a55b3c72effd3da6eeb5256c8`.
These are local component/replay results, with zero new Windows observations and
zero whole-PE pairs. Independent Sol review and new-commit CI remain required.

All three workflows for both reviewed predecessors completed successfully:
214d585: 40971700846, 40971694667, 40971694772;
cfaa71f: 40972514039, 40972507526, 40972507509.
Their success does not explain or erase the historical Windows timeouts.

The selected C++ predecessor is now connected for the tested search domain:
registration/owner/record authority comes from the same canonical chain, normal
captured ESP is refined against the live stack without modifying CONTEXT bytes,
and actual original prefix/common/PTD/RET execution precedes a distinct single-use
selected-node receipt. The 31-case selector includes ten new selected-C++ cases.
See THREAD-CHAIN.md. Remaining producers are actual delivery/capture, module/FLS
acquisition and incoming-chain containment; unbound C++ search backend, other
search dispositions, noncontinuable/nested/collided paths and termination remain
explicit rejections. This closes a connected component path, not whole-PE startup.

Selected-search validation: all 223 CRT tests passed (one observation-dependent
case separately passed), all-target Clippy passed with warnings denied, and the
retained artifact checker passed all 31 ordered cases and five recorded wrapper
comparisons. PE hash is unchanged; current harness hash is in the evidence JSON.
There are zero new Windows observations and zero whole-PE pairs. Review of
4a44eca confirmed eight jobs passed in each Rust workflow, final Linux jobs
123803368463/123803467001 still active, and pinned startup40975183290 passed.
These conclusions do not validate the new changed head or diagnose old timeouts.

Pending-call acquisition now produces record code/flags/zero parameter count from
validated RaiseException arguments on fresh checked storage; all other record and
CONTEXT fields retain unknown/supplied status. The34-case ordered selector checks
producer replay, stale event, initialized storage rejection, unknown-byte retention
and replacement of the produced record. Incoming Owned nodes must still be live
and linked; borrowed or unbound source shapes reject. Registry validation alone
does not acquire incoming handler storage or effects. See THREAD-CHAIN.md for the
remaining nonempty EH4 selection/containment and actual captured-context gate.

| Delivery input | Current producer or remaining assumption |
| --- | --- |
| Record storage | Supplied fresh checked 80-byte region; allocation not acquired here |
| Record code, parameter count | Produced once from the live validated zero-parameter RaiseException CALL |
| Noncontinuable flag bit | Produced from dwExceptionFlags; all reserved/system bits stay unknown until a separate delivered-flags contract |
| Nested-record link | Explicit supplied null input for the existing non-nested domain |
| Exception address, unused information | Unknown; never filled with zero or guessed from CALL PC |
| Saved CONTEXT / ESP | Supplied captured object; exact value/known-mask and identity/lifetime validated. Numeric or unambiguous masked bound observations; no acquisition claim |
| Saved general registers / flags | Never copied from raised-call registers as a substitute for capture |
| Incoming owned predecessor | Must be a live linked registration; handler storage/effects still need composition |
| Borrowed root / dispatcher | Reject without containment proof; no default incoming handler or empty-chain assumption |

Capture-boundary checkpoint validation passed223 CRT tests, all-target Clippy and
retained-artifact replay, including34 ordered cases and five recorded wrapper
comparisons. The observation-dependent case passed separately. Current source
hashes are in the evidence JSON; there are zero fresh Windows observations and
zero whole-PE pairs. The reviewed05fc38c Rust jobs each had eight successes and
final Linux jobs123807523849/123807819719 pending; pinned original-probes job
123806170041 was pending at inspection. Historical timeouts remain undiagnosed.

Epoch-root binding now closes another incoming ownership check: cursor creation
retains the established root, every subsequent transition rechecks epoch previous
head and selected identity, and the predecessor walk must reach that exact live
linked root. The37-case selector adds changed epoch head/selection and retired
incoming owner, retaining record/capture/code/lifetime cases. This is root
attribution, not authorization to run an unknown incoming handler.

The live capture representation now preserves partial known bits and derives only
unambiguous stack comparisons. Normal EH4 and selected C++ original paths share
that view; partial values carry no numeric stack pointer and cannot satisfy the
numeric unwind contract. The source event, object lifetime and exact value/mask
remain checked before effects and receipt consumption. The 47 ordered cases and
independent exhaustive small-bit oracle are described in THREAD-CHAIN.md.

Actual capture acquisition remains open: even the new partial high-bit knowledge
is a supplied component input. The older opaque OwnedEvent predicates have a
different source/lifetime contract. Connecting them requires a same-event,
code/effect observation certificate, not selecting a numeric witness or asserting
unknown high bits. A wholly unknown capture, raw numerical extraction, changed
capture and stale storage still reject. Full startup/rcedit stays unsupported.

Review correction: the argument producer's full ExceptionFlags mask was not
justified. It now produces only known bit0; reserved/system bits stay unknown.
The component explicitly supplies delivered flags0 only after testing that the
partial record cannot bind as a fully known delivery. Code/count production is
unchanged. Compiled proof mutations independently demonstrate detection of both
a removed root guard and the old full-known flag store. Complete flag delivery
and capture remain open effects; no whole-PE compatibility is inferred.

Current review validation passed223 CRT tests, all-target Clippy and full retained
artifact replay, including37 ordered cases and five recorded wrapper comparisons.
The observation-dependent case passed separately. Both independently compiled
mutants were caught by their exact expected assertions. The evidence JSON retains
PE/harness/mutant hashes. New Windows observations and whole-PE pairs remain zero.
Reviewed12e0e22 pinned jobs passed; Rust runs40977516921/40977509102 each had eight
passed jobs and final Linux123811087881/123810696537 still active at inspection.
No failure was observed; passing checks do not explain historical timeouts.

The reviewed 36eeb34 completed all three workflows successfully:
40979161128,40979155479 and40979155599. These are exact predecessor conclusions,
not validation of this changed capture-view head or a diagnosis of old timeouts.

Capture-view validation passed all 223 CRT tests, all 175 root tests, all-target
Clippy and the retained-artifact checker. The observation-dependent test passed
separately. The checker retained five recorded Windows wrapper comparisons and
executed all 47 ordered cases; zero fresh Windows observations and zero whole-PE
pairs are claimed. The compiled upper-bound mutant was caught by the intended
unexpected-admission assertion. Current PE, harness, unwind and mutation hashes
are retained in evidence/cxx-unwind-component.json. No historical timeout cause
was established.

Independent review of 2cc9c77 found no runtime authority defect. Two added strict
cases cover knowledge-mask-only changes and the narrower C++ stack region, raising
the ordered selector to 49 cases. The precise producer/certificate/lifecycle work
needed to remove supplied capture knowledge is specified in
[CAPTURE-ACQUISITION.md](CAPTURE-ACQUISITION.md). Bit-range predicates alone do not
provide that authority; unknown raw capture and unproved effects still reject.

Sol review reproduced six context-proof tests, all 49 ordered native cases and
the full retained-artifact replay with five recorded wrapper comparisons. The
updated capture mutant compiled and failed its intended assertion. There are
zero fresh Windows observations or whole-PE pairs. The reviewed base's 223 CRT
and 175 root tests remain base evidence; this review changes tests and documents,
not runtime semantics. Current harness and mutant hashes are in the evidence JSON.

Acquisition-certificate implementation uncovered and fixed erased pre-selector
CONTEXT/TEB reads in the context-helper proof. Per-path observation validation now
rejects them; the previous decision tree alone was not a no-observation proof.
A separately compiled guard-removal mutant confirms the counterexample. See
CAPTURE-ACQUISITION.md. Whole-event observation composition and the same-event
capture lifetime issuer remain unimplemented; no supplied value gained authority.

Independent review of 72974f0 adds shared-return CONTEXT/FS read regressions and a
compiled bypass-permission-leak mutant; no further runtime defect was found.
Related filter/normalizer/prefix inspection is bounded and grants no whole-event
capture certificate. The original Windows output-probe timed out after 15 seconds
in run40983904709/job123830245636. The diagnostic artifact was uploaded as
12945762783; available logs do not establish original stdout/stderr or root cause.
The evidence metadata is retained in evidence/windows-output-probe-72974f0.json.
No retry or timeout relaxation was used. Historical failures remain unresolved.

Review validation passed all 225 CRT tests, including eight context-proof tests
and the existing 49 ordered cases, plus all-target Clippy. The observation-dependent
test remains separately verified at 72974f0; this test/documentation-only review
adds no generated runtime change or new Windows/whole-PE comparison.

## Connected unknown-context checkpoint

The no-read selector path now executes both original ordered handlers with all
716 context bytes unknown (70 ordered cases, including 21 new lease scenarios).
The event-issued lease binds source CALL, registry/epoch, frame/event generations,
storage capability and exact helper proof. Raw reads/writes reject through aliases;
no numeric ESP or captured-stack predicate is created. Event/epoch failure and
receipt consumption revoke the lease without rolling back previous effects.
See [capture contract and exact remaining gate](CAPTURE-ACQUISITION.md#connected-no-read-lease-current-implementation).

This removes supplied capture **values** from the component path, not its supplied
delivery flags/nested link, incoming root, module/PTD/FLS initialization or complete
API-effect assumptions. A static whole-event observation/producer certificate is
still missing; runtime rejection is not whole-program equivalence. Full startup
and rcedit remain rejected. No fresh Windows observation or whole-PE pair follows
from the 20 new native scenarios.

Reviewed baseline 5615c2b completed Rust40984728593/40984721250 and
pinned40984721318 successfully. For72974f0, push40983899668 and pinned40983899745
passed; PR40983904709 failed the preserved original-Windows output-probe timeout
(job123830245636). That difference does not establish a cause or erase the failure.
The changed lease implementation requires its own exact-head CI.

Sol review of c3be6ab found no further runtime defect and adds a strict failure
inside the original handler, after a retained write. The same lease is revoked;
no completed receipt or capture value is produced. The next executable gate is
the closed ContinueSearch observation/call summary described in
[the review](CAPTURE-ACQUISITION.md#sol-review-of-c3be6ab), followed by its producer
and API/import provenance obligations. Runtime success does not issue that proof.

## Bound helper composition; concrete producer barrier

The ordered EH4 emitter now composes the actual normalizer, guard/security and
context proofs by target, byte extent, event domain, cookie and scope header,
and emits the callbacks from those proofs. Changed live helper bytes reject.
This closes a source-binding gap, not complete capture acquisition or a
whole-event effect proof. See [the contract and counterexamples](CAPTURE-ACQUISITION.md#callercallee-composition-and-the-remaining-ptd-producer).

With the first handler completed, unknown PTD[32] rejects at original CMP 0x403d9c;
a null FLS slot reaches unbound CALL 0x402906→0x402bef. The next cohesive gate is
that C++ lazy producer's setter/sentinel, allocation/publication/rollback/free,
LastError and termination effects, using the actual module/fiber/slot ownership.
A 40-byte zeroed object must come from the proven allocator. Supplied initialization
and a successful component run cannot discharge those obligations. Full startup,
rcedit and historical timeout causes remain unresolved.

Independent Sol review of 5c9d4c2 found no helper-composition defect. The actual
setter is resolver index 3/FlsSetValue with a distinct TlsSetValue fallback, not
the getter's index 2 contract. A new allocation regression identifies the next
code-level blocker: heap Buffer capability versus rooted ThreadData role. Keep
the same heap identity and aliases through a checked PTD view derived from the
allocator effect; copying/retagging must not create authority. Connect that view
to setter publication/rollback, free and slot/fiber lifetime. See the review in
CAPTURE-ACQUISITION.md and evidence/ptd-setter-review.json. No runtime semantics or
admission expanded in this review.

### Heap PTD allocation/view and lazy setter checkpoint

The allocator's Buffer identity now survives a checked, single-use PTD object
view; aliases share the same storage and lifetime. The native component executes
original getter/setter control flow, allocator/free thunks, the decoded calloc
body under explicit backend contracts, publication/rollback and LastError restore.
Free-body effects remain checked callback inputs. FLS failure leaves value
knowledge unknown, and cleanup failure preserves earlier effects.

The ordered common handler still uses its cached-only getter. Connect the lazy
producer through that pending-event adapter next, retaining explicit heap,
new-handler/errno, setter outcome and module/fiber/slot contracts. Required-getter
termination, free body, actual acquisition and incoming-chain containment remain
unclosed. This checkpoint adds no whole-PE acceptance. See
[the view contract and review gate](CAPTURE-ACQUISITION.md#heap-ptd-view-and-original-setter-connection)
and [preserved predecessor CI failures](evidence/ci-db4fc00.json).

### Checked common-handler lazy producer composition

The original common dispatcher can now call the live lazy PTD producer through
its protected call boundary, validate the actual completed child result and
published root, then execute original PTD reads and return. Twenty-four native
cases cover the composition; initial module/fiber/slot and API effects remain
explicit inputs. The pending-event ordered adapter is still cached-only.

Next close the original free body's normal-return HeapFree failure path with an
owned API outcome and justified alias/lifetime/errno effects. The existing memory
kernel has successful retirement and explicit rejection, not a Windows FALSE
outcome. Do not remove the missing-free check or infer atomicity. Then carry the
producer through the pending-event delivery lease. Details and the predecessor
CI conclusions are in [the common-handler contract](CAPTURE-ACQUISITION.md#common-handler-with-the-live-lazy-ptd-producer).

### HeapFree failure and ordered lazy producer

The original free body, error mapper/search/table, errno router and owned errno
store now compose on declared heap/API/UCRT PTD inputs. FALSE revokes allocation
access knowledge without claiming successful release or unchanged memory; a
normal cleanup receipt requires the actual checked return. Earlier effects
remain when a later step rejects. The ordered C++ handler now invokes the
original lazy producer within its pending-event child lease (84 ordered cases,
eight new); actual delivery is still supplied. No whole-PE acceptance is added.

Next integrate the actual calloc and UCRT PTD producers into that pending adapter.
Its current allocator/errno callbacks are explicit cuts. The existing calloc
component's initialization token is not general live-heap authority; do not pass
an expired startup token through exception delivery. New-handler, recursive errno,
required-getter termination, and lazy-path unwind remain rejected. See
[the connected contract](CAPTURE-ACQUISITION.md#original-free-failure-and-pending-event-lazy-acquisition).

### Original calloc under live heap authority

The ordered lazy path now executes original calloc and its mode getter under a
separate live process-heap contract; no expired initialization token or descriptor
authority is used. Nine independent calloc cases and 85 ordered cases exercise
success, retry/error and rejected ownership. Original HeapAlloc outcomes and
new-handler results remain declared inputs. Allocation failure in the pending
path explicitly rejects at original UCRT errno acquisition, retaining its FLS
sentinel and issuing no success receipt.

Next connect UCRT getter 0x40a332's prolog/epilog to the canonical delivery-child
registry head. Its current local FS view cannot stand in for that ownership;
UCRT and C++ FLS slots remain distinct. Then route both calloc and free errno
access through this producer. See [the exact gate](CAPTURE-ACQUISITION.md#exact-remaining-errno-producer-integration).

## Registered UCRT errno producer (current)

The earlier canonical-registry gate is now connected for a live, already bound
UCRT PTD/FLS slot. Original calloc/free failure → errno router → getter/prolog →
FLS lookup → epilog → field store execute under the same delivery child epoch.
The suspended parent, predecessor order and actual allocation identity survive.
The allocation-failure path now proceeds through sentinel reset to the explicit
required-PTD termination rejection, rather than stopping at an errno callback.
Initial UCRT PTD/FLS creation, null-slot lazy initialization, dynamic getter,
actual OS delivery and termination effects are still supplied or unbound.
See [contract and remaining executable gate](CAPTURE-ACQUISITION.md#registered-ucrt-errno-acquisition)
and [evidence](evidence/registered-ucrt.json). This adds no whole-image support.

## Connected required-PTD abort entry

The null-PTD failure now follows original abort entry4077ff → signal-query caller
40cbcf → explicit rejection at locked helper40cafd. Complete original caller
arguments and RET12 semantics are executed; query results are supplied only in
separately labeled conformance tests. Next bind helper40cafd's actual EH4 frame,
lock3, encoded signal cell/cookie and finally unlock before extending dispatch,
fast-fail/reporting or exit. This is component progress, with no new whole-PE
acceptance. [Evidence and exact next gate](CAPTURE-ACQUISITION.md#reviewed-registry-and-connected-abort-caller).

## Locked query now executed

Required-PTD → abort entry/query → helper40cafd now executes the actual registered
EH4 frame, lock3, decoded signal-cell value and finally/unlock, retiring through
original RET12. Current rejection moves to abort407804's TEST/dispatch/report/exit
continuation. Initial encoded-cell/module/lock state is still supplied, and
proof rejection does not simulate exceptional finally execution. Twelve negative/
normal cases and an old-guard mutant protect ownership and prior effects.
[Current contract and next gate](CAPTURE-ACQUISITION.md#connected-locked-signal-query).

## Abort branches now executed

Original407804 query decision and flags41c128 choose actual unbound signal22
call40cc14, feature23 import41501c or exit wrapper407004. The exit wrapper's
original pushes now reach shared exit406e69 with3/2/0; shared exit itself remains
unbound. Unknown conditions reject, no missing call supplies success, and owner/
lifetime checks preserve prior effects. Next establish the original mode2 exit
policy/FS frame and separate signal dispatch contracts.
[Current branch/exit evidence](CAPTURE-ACQUISITION.md#original-abort-branches-and-exit-wrapper).

## Inline shared exit now reached

Abort's original exit wrapper → `0x406e69` now installs the distinct inline record
under canonical thread/event ownership, then executes the existing original RET0 helper at0x401bbc and PUSH EAX; it rejects at actual managed-runtime
query `0x401d51` (GetModuleHandleW plus checked PE-header reads). A supplied return
mode reaches manager `0x406cfa` and rejects. The original unlink/LEAVE/RET has
separate native component coverage; body-to-return and process termination are
not connected. Missing effects retain live frames, not successful cleanup.
[Current lifetime boundary and next executable gate](CAPTURE-ACQUISITION.md#inline-shared-exit-record-and-return-lifetime).

## Checked image query available with explicit main-image authority

Original401d51 now executes against a lifetime-bound module image and original
header reads. Supplying the independently modeled main-image role lets shared
exit reach manager406cfa (native) or managed termination406f55; both remain rejected.
The default pending path still lacks the actual startup main-image producer.
[Current checked-image contract](CAPTURE-ACQUISITION.md#checked-module-image-query-component).

The remaining main-image issuer must derive identity and mapping from the loaded
input PE/process bootstrap, bind the complete mapping once per process, and survive
ordinary thread/fiber changes while expiring at process teardown. It must not issue
an owned LoadLibrary reference or permit ordinary FreeLibrary receipt replay to
retire the process identity. Adversarial acceptance should cover duplicate issuers,
foreign/replaced mappings, process teardown, fake main-role assignment and concurrent
owned references to the same module. This is the concrete next ownership contract;
current supplied image inputs do not establish it.

## Canonical process-image ownership implemented

Bootstrap now owns the main-image mapping once per runtime, independently of
acquired-module references. The exit front retrieves that canonical authority;
thread/fiber/event transitions retain it and process closure expires it. The next
input cut is composition of the validated original PE mapping with existing CRT
module/record maps before bootstrap emission, followed by manager406cfa and the
remaining termination effects. [Contract and evidence limits](CAPTURE-ACQUISITION.md#canonical-process-owned-main-image).

## Raw PE sections now compose with process-image authority

`bootstrap_pe32` installs validated initial headers/sections, preserves their
permissions and publishes the canonical process image only after the mapping
transaction succeeds. The original managed query executes against those headers;
recorded authored input also maps without rewriting its bytes. No loader effects
or converter admission are granted. Next replace the separately mapped FILE-array
anchor with a view into the existing writable image section, then migrate cookie/
record views before connecting the remaining manager/termination effects.
[Contract, executable boundary and reproduction](CAPTURE-ACQUISITION.md#section-backed-pe32-bootstrap).

## FILE anchor now shares mapped data identity

The raw-PE constructor now adopts a bounded FILE view inside the existing writable
section; the section capability is also the runtime anchor. The original header
query executes after initialization ends, while FILE/module aliases retain the
same lock, opaque-byte and typed-field policy. No lock or CRT initialization is
inferred from mapped bytes. This closes the separate FILE mapping gap in the
preceding section. Next migrate cookie/startup-record producers to section views
and connect the manager/termination effects. [Contract and rejection boundary](CAPTURE-ACQUISITION.md#file-anchor-adopts-canonical-image-storage).

## Original cookie/record storage composition connected

The original cookie initializer's existing-cookie path now writes the complement
in canonical `.data`; the original record prolog and checked epilog use that same
cookie, mapped FILE anchor and live stack. Successful cases supply an established
cookie explicitly. Actual default input still rejects at entropy helper401b24,
whose four OS acquisition effects and stack-local identity are not implemented.
The next gate is that real producer, followed by startup40161f; no recorded entropy
or initializer success is inferred. [Exact evidence and next contract](CAPTURE-ACQUISITION.md#cookie-stores-and-original-record-initialization-share-mapped-data).

### Default-cookie helper execution connected; acquisition still supplied

The original 77-byte helper401b24 now executes through shared SIMD/scalar lowering,
protected calls, checked eight-byte local writes and original cookie repair/stores.
Successful cases feed the produced cookie into the original registered normal
record lifecycle without overwriting the produced value.
Actual PE bytes/imports bind the component. 16 helper/initializer cases and nine
API boundary cases check strict results; 33 independent vector cases check flags,
unknown bits, register choices and whole-store preflight. Numeric process/thread
IDs and individual time/counter observations remain supplied contract inputs.
No native acquisition, fresh Windows entropy pair or full startup is claimed.
Next replace those inputs with justified live producers and connect40161f; see
[contract and primary sources](CAPTURE-ACQUISITION.md#default-cookie-helper-executes-under-explicit-acquisition-inputs).

### Bounded native Linux identity/clock producer connected

The cookie component can now acquire actual namespace PID/TID and UTC/monotonic
clock observations under a live canonical initialization binding. It executes
original helper/initializer/registered-record instructions with that producer.
Cross-thread/runtime use, changed IDs, stale initialization, malformed procfs
identity and clock range/reversal reject. This closes supplied acquisition for
the declared single-process Linux entropy domain, not general QPC/Windows ID
semantics. Next connect startup40161f's actual caller sequence and remaining
manager/locale/FILE initialization. No new Windows or whole-PE pair.

Original-entry inspection for the next gate: PE AddressOfEntryPoint is4017a4.
Its ten unchanged bytes are `e8c8030000e971feffff`: CALL401b71 then JMP40161f.
The latter starts with PUSH14/PUSH41b238/CALL401e60 (existing normal prolog),
then PUSH1/CALL401945 and tests AL before later startup work. Lift the entry
shim and bind this first initializer outcome from actual code, including its
failure edge40178e; do not jump directly to Main. Root activation, incoming
thread state and remaining initializer effects stay proof prerequisites. This
is a concrete Sol implementation/review scope; escalate a reproduced ownership
or external-effect uncertainty, not routine CI work.

### Entry4017a4 now reaches the original processor-feature call

A connected bounded native path runs the original entry CALL/JMP, cookie producer,
startup EH4 prolog, initializer401945 and CPU-prefix writes. Its first unsupported
operation is the actual IsProcessorFeaturePresent(10) call at401ebe/IAT41501c.
No injected success passes that boundary. Canonical41c058 bit0 and41ccb8=0 writes
survive the rejection. Root activation/incoming chain remain component inputs;
there is no full unchanged-binary entry-to-exit result. Nine cases and81 byte
mutants protect binding/lifetime/failure behavior. Next unify CPUID (five sites),
XGETBV (one site), enabled OS/SIMD state and scalar feature-cache semantics for
401ea5..4021be before binding feature-query results. Full utility support remains
blocked by later initializer, loader, delivery and exit gates.

### CPU observation and classifier return to40195a

- Executed: original entry/cookie/EH4 startup/401945/401ea5, all reachable scalar
  CPUID/XGETBV classifier branches and original RET under checked observations.
- Actual producers: Linux x86-64 CPU/OS queries and prior native IDs/clocks in a
  connected component case. Synthetic CPU profiles remain independently labeled.
- Support boundary: observations are confined to this closed classifier. They
  cannot enable unsupported instructions or authorize later feature-selected
  library paths. Default emitters still reject CPU-query effects without binding.
- First unsupported call:40195a→4024ca, before its lock construction4029b4 and
  FLS acquisition/publication402963. Preserve count/slot/cleanup order when
  connecting these existing ownership components to actual startup producers.
- Still supplied/unproved: root activation/incoming chain, OS delivery and
  containment, later locale/FILE initialization, full formatting and physical
  exit. No full startup/rcedit claim. See [CPU-FEATURES.md](CPU-FEATURES.md).

### Startup module dispatcher and lock resolver prefix

Original entry now reaches402c42→402a53 through4024ca/4029b4/402c2d, retaining
prior cookie/classifier writes and active original frames. No lock constructor
or FLS allocation outcome is supplied on that connected entry path. Separate
component cases execute module/lock/FLS control with explicit observations and
stop before unsupported publication authority. Next: shared dynamic constructor
and FlsAlloc resolver bindings, followed by module-backed bootstrap object41ccc4
and callback4028a7 lifecycle. This object must be distinguished from the recursive
FFFFFFFF marker. See [STARTUP-MODULES.md](STARTUP-MODULES.md).

### Mapped resolver and process-wide FLS index

Original entry now executes402c42→402a53→402af3 and stops at the actual
LoadLibraryExW call402b00/IAT415074. Live code, canonical mapped arguments,
module/export lifetime and cache publication use the shared resolver. Actual
load/API-set/DllMain/TLS effects remain unbound. Component allocation outcomes
now issue a process index distinct from the current fiber value lease; the
original control cases preserve global publication and failure order. There
is no actual FlsAlloc/FlsSetValue producer or bootstrap-PTD publication yet.
See [STARTUP-RESOLVER.md](STARTUP-RESOLVER.md) for evidence, stationary-fiber
limits and the next loader/constructor/bootstrap-object gates. Full startup
and rcedit remain unsupported.

### Resident ordinary-DLL acquisition

Original load helper402af3 now executes its LoadLibraryExW call through a
checked resident-module backend when an explicit initialized ordinary-DLL
process environment is supplied. Reference acquisition and lifetime are real
runtime transitions; missing authority/search/API-set cases reject. The default
original entry still stops at402b00 because api-ms-win-core-synch-l1-2-0 mapping
and initialization effects are not established. Next: justify the system-module
namespace and native export contracts, then constructor/FLS effects. See
[RESIDENT-LOADER.md](RESIDENT-LOADER.md). No new whole-PE support.

### API-set namespace and provider initialization

The default entry remains at LoadLibraryExW402b00. A frozen x86 Server2022/20348
observer now measures contract→load-host→export-host identity and reference
survival, independently of the converter. Missing/ambiguous evidence rejects;
no observation issues native initialization authority. Next: a process-owned,
initialized lock provider with documented ABI/effects and failure-atomic export
publication, then dynamic FLS. See [API-SET-BOUNDARY.md](API-SET-BOUNDARY.md).
This is a measurement gate, not actual acquisition or new PE/ELF evidence.

### Native provider ownership prerequisite

The emitted runtime now constructs a process-owned native provider registry,
separates process roots from acquired references, and keeps load/source ownership
distinct from the target borrowed by a forwarded export descriptor. Pending,
failed, replayed and stale lifetimes reject. Descriptors cannot become callable
or enter a function cache without an implementation issuer; actual native API
semantics and original entry mapping at402b00 remain open. See
[PROVIDER-OWNERSHIP.md](PROVIDER-OWNERSHIP.md). No Windows initialization or new
whole-PE execution follows from registry construction.

### Native synchronization operation

A specific implementation issuer now binds InitializeCriticalSectionEx to actual
owned global-lock construction and a checked RET12 adapter. Native tracking
allocation, opaque object storage, recursive thread ownership, deletion ordering
and provider lifetime are tested. Resource-failure BOOL/LastError effects and
full API-set/system-provider initialization remain unclosed at402b00. See
[NATIVE-SYNCHRONIZATION.md](NATIVE-SYNCHRONIZATION.md); no new Windows pairs or
whole-image admission follow from these component tests.

### Independent critical-section conformance gate

A frozen authored x86 Windows observer and native operation trace now cover two
spin configurations, recursion, deletion/reinitialization and adjacent bytes.
Fresh Windows/native component comparison is a separate CI gate; no runtime
support widening occurs. It cannot close allocation-failure error behavior or
API-set initialization at402b00. See [SYNC-CONFORMANCE.md](SYNC-CONFORMANCE.md)
for the explicit resource-contract decision required before admission.

## Synchronization resource checkpoint

The native global-object map, tracking vector and recursive lease vector now use
fixed 32-slot storage; checked argument/return reads no longer allocate temporary
tag vectors. Allocation-denial and partial-construction tests cover the actual
stdcall operation and failure ordering. This closes native per-call bookkeeping,
not Windows Ex BOOL-zero/LastError equivalence or provider initial state. Original
entry still rejects LoadLibraryExW at0x402b00. See [SYNC-RESOURCES.md](SYNC-RESOURCES.md)
for the exact resource contract and next external-effect decision; no API-set
admission follows merely from fixed storage.

Provider initialization failure evidence is now frozen independently using an
authored rejecting DllMain and accepting control, in a separate Windows job.
This closes no execution gate until measured; failed-load namespace rollback is
separate from rollback of arbitrary initializer effects. Original entry remains
0x402b00. See [PROVIDER-FAILURE.md](PROVIDER-FAILURE.md).

Original ordinary-DLL attach failure is now measured: Windows job124049912153
returned1114 twice with no acquirable failed module; the accepting control
retained/unloaded exactly across its two owned releases. This is evidence-only
progress. No detach/effect trace or system API-set initialization proof was issued;
original entry still rejects0x402b00. See PROVIDER-FAILURE.md and its JSON evidence.

The native synchronization replacement now has a connected construction/cleanup
transaction and actual owned-reference acquisition/release, executing only its
implemented export. This is native component progress; original entry remains
blocked at0x402b00. Windows DLL initialization, error1114 and ordinary final-release
unloading are not substituted by the process-owned native root policy. See
[NATIVE-PROVIDER-INITIALIZATION.md](NATIVE-PROVIDER-INITIALIZATION.md).

### Explicit native synchronization profile reaches the original export lookup

The versioned opt-in `w2l-native-sync-20348-v1` component environment now prepares
its actual process-owned replacement provider before entry. Original instructions
execute LoadLibraryExW402b00, helper return and cache publication41cd0c, reaching
GetProcAddress402ae0/IAT415070. Default admission still rejects402b00. Reference
bookkeeping and loader validation use fixed storage; capacity rejection is an
internal bound, never a fabricated Windows null/error. Future synchronization
failure behavior is a separate API gate rather than a prerequisite for acquisition.
Next bind named export lookup and original function-cache publication under live
source/target authority. See [minimum predicates and scope](NATIVE-PLATFORM-PROFILE.md).
No fresh Windows or whole-PE pair; complete environment/resource proof is still open.

### Named native export and function cache now execute

Under the explicit native profile, original GetProcAddress402ae0 now returns the
unique live implemented export, and original XCHG402aef publishes function41cd24.
Execution stops explicitly at constructor tail402c47, before guard/indirect API
invocation; default entry still rejects402b00. Lookup validates complete source
publication and actual target lifetime without creating call authority. Next lift
402c47..402c73 with actual arguments, guard, dynamic call and fallback semantics.
See [NAMED-NATIVE-EXPORT.md](NAMED-NATIVE-EXPORT.md). No new whole-PE pairs.

### Constructor tail reaches its checked indirect API call

Explicit-profile entry now executes original402c47..402c61 including resolver
argument cleanup, target preservation, guard stub and protected stdcall call
setup. The live function/source/target and object argument are validated; no lock
is constructed. The exact boundary is InitializeCriticalSectionEx failure/resource
contract at402c61. Default admission still rejects402b00. Next resolve that API
relation, then original constructor RET/count publication and FLS. See
[CONSTRUCTOR-TAIL.md](CONSTRUCTOR-TAIL.md). No new whole-PE pairs.
