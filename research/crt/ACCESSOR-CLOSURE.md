# SUB-546: accessor closure decision

**No-go for composing the real `__p__commode` call with the owned zero-store and
sentinel.** The public description identifies the returned object; it does not
provide a complete external-effect frame for this internal interface. The current
evidence does not establish one either. Keep the production ordinary-CRT rejection
and the research example's default blocked result. This is a decision about the
available proof, not a finding that Windows actually performs an unexpected write.

## Evidence and requirements

Primary Microsoft documentation read 2026-10-26. Requirements below are independently
specified; no Microsoft or Wine implementation source is imported or translated.

| Primary source | What it supports | What it does not establish here |
| --- | --- | --- |
| [__p__commode](https://learn.microsoft.com/en-us/cpp/c-runtime-library/p-commode?view=msvc-170) | No-argument accessor returning a pointer to the default file-commit-mode global; application state by default | Exhaustive reads/writes, initialization, error/TLS or exceptional behavior |
| [Internal CRT interfaces](https://learn.microsoft.com/en-us/cpp/c-runtime-library/internal-crt-globals-and-functions?view=msvc-170) | These are implementation details and can change between versions | Stable implementation across UCRT builds, or a supported application API |
| [Global CRT state](https://learn.microsoft.com/en-us/cpp/c-runtime-library/global-state?view=msvc-170) | Application/OS state separation and /MT component isolation | Cross-process, cross-instance or reload pointer identity; absence of thread-specific selection |
| [x86 arguments and returns](https://learn.microsoft.com/en-us/cpp/cpp/argument-passing-and-naming-conventions?view=msvc-170), [cdecl](https://learn.microsoft.com/en-us/cpp/cpp/cdecl?view=msvc-170) | EAX return, preserved ESI/EDI/EBX/EBP and caller argument cleanup for a conforming x86 call | Known ECX/EDX/arithmetic flags, numeric initial ESP, or memory purity |
| [errno and _doserrno](https://learn.microsoft.com/en-us/cpp/c-runtime-library/errno-doserrno-sys-errlist-and-sys-nerr?view=msvc-170) | Startup initializes these error values; the macros access runtime-managed cells; later calls can change them | An accessor-specific promise that all error or TLS state is preserved |
| [GetLastError](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror), [SetLastError](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setlasterror) | Per-thread last-error storage and immediate observation; setting an application-defined value is supported | A general no-write property for functions returning successfully |
| [WOW64 file redirection](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector), [final handle path](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlea) | A 32-bit process can resolve System32 to a different file than a 64-bit observer; the final file-handle path identifies the opened file | A path string alone does not identify loaded bytes |
| [SEH](https://learn.microsoft.com/en-us/cpp/cpp/structured-exception-handling-c-cpp?view=msvc-170) | Faults/unwinding can affect control flow and cleanup | That this accessor raises an exception, or that all its executions are exception-free |

The absence of a listed failure code is not evidence of a hidden failure code. We
must neither invent one nor replace an unproved path with successful continuation.
Valid mapped memory and fault-free execution are already explicit project domain
assumptions. They do not discharge possible initialization or external-call effects.
The API's specified pointer return supports the ordinary successful return shape;
it alone cannot certify every path or the lifetime of a chosen synthetic resource.

## Exact authored caller and runtime evidence

`check_commode.bind` and the Rust external-cell binder retain the unchanged PE hash,
caller RVA0x1043..0x1058, helper0x16c0, thunk0x1d06, HIGHLOW0x1d08, and IAT0x20a8
named `api-ms-win-crt-stdio-l1-1-0.dll!__p__commode`. Helper return0 is saved in ESI;
the accessor result is used by the four-byte store at0x1051, after PUSH1, before
CALL0x13e0. The exact bytes and source/compiler provenance are retained by the
existing compiler inventory. The baseline binary is not edited for this research.

Prior CI40372168704/artifact12672592709 bound original SHA256
`7badae2013bb44381b367c7cbb290e75cf992be84976235d3788e566d52085c0`.
Each new CI report binds its own compiler-produced original, since build timestamps
can change the PE hash; Windows and Linux must consume that same artifact.

| Evidence class | Established | Remaining gap |
| --- | --- | --- |
| Static unchanged authored PE | Exact call/store chain, import name, relocation, ESI=0 | IAT name does not identify the loaded accessor's complete instruction/effect graph |
| Earlier separate /MD probes | Returned word belongs to loaded ucrtbase.dll; repeated/joined-thread pointers agree in each measured process | Not an observation at the original callback; not a first-ever accessor call or arbitrary thread/runtime guarantee |
| Earlier separate /MT probes | Word belongs to the authored executable in these builds | Not the /MD original's runtime instance |
| Prior observed runtime metadata | UCRT version10.0.26100.33648, per-run module hashes and actual observed bases | An on-disk module hash and a data-owner base are not a proof of the executing code's effects or loaded-byte identity |
| New separate /MD error probe | Records three error values around two explicit calls in each of two processes; owner metadata and hypotheses retained | Cannot observe all TLS, allocations, locks, callbacks, first-startup state or all exceptional paths |
| Rust/model isolated store | Lifetime/owner-bound zero-store can be represented under an explicit hypothetical frame | No legitimate issuer for that frame from the real accessor |

No inference combines the separately observed original run's module list with a
probe's pointer to assert that both executions used the same live object. Identity
includes the process, runtime instance and generation. Existing runtime observers
remain separately labeled; original ordinary Windows baseline behavior is distinct.

## Needed compositional summary

The following is a **required summary**, not an implemented or proven replacement:

1. At the exact call, a known initialized app-mode x86 CRT instance is live and
   remains loaded. All earlier startup effects and mappings needed by the accessor
   must be established, including any thread/fiber-local selector. No concurrent
   writer/unload, asynchronous callback, code/IAT modification or external mutation
   is admitted in this bounded domain. These are explicit premises to justify,
   not facts inferred from a single-threaded sample.
2. On normal return, EAX names the complete live aligned four-byte commit-mode
   object in that instance. All aliases refer to that object, with no alias into
   the authored image, saved registers, return words or active stack. No numeric
   VA alone grants authority. Preserve ESI/EDI/EBX/EBP; conservatively forget
   ECX/EDX and arithmetic flags. The no-argument cdecl call leaves caller ESP
   unchanged after its return; do not invent a numeric stack base.
3. Bound **all** accessor writes and externally observable actions. If it reads
   or initializes TLS, changes error state, invokes another function, allocates,
   acquires locks or can fail/nonreturn, model that effect or demonstrate it absent
   under the admitted preconditions. Havoc alone is insufficient if the generated
   program must reproduce later reads/flush/termination behavior. Unobserved host
   internals need not be mirrored if a valid abstraction proves them irrelevant;
   current evidence contains no such noninterference proof.
4. Only then issue a private owned-cell capability. The caller writes four zero
   bytes without reading prior contents. Its PUSH/MOV preserve the call's unknown
   arithmetic flags. The subsequent sentinel may establish its own flags but
   cannot repair unknown memory, lifetime or earlier observable effects.
5. Complete earlier imports and later initialization/exit registration separately.
   This three-operation composition would still not close ordinary CRT startup,
   stdout/flush/exit or general application behavior.

The missing item is principally **3**, with unresolved runtime-selection/lifetime
premises in1 and2. Default blocking remains sticky for unknown effects, stale
runtime identity, concurrent mutation, exceptional/failing/nonreturning paths.
A subsequent successful sample cannot erase a previous proof obligation. The
negative tests exercise that conservative composition rule in the existing test
model; they do not simulate Windows failure implementations or force real faults.

## Frozen observation protocol

`accessor_probe.c`, compiled x86 `/W4 /WX /O2 /MD`, is separately authored and runs
after its own CRT startup. It resolves `_errno()` and `__doserrno()` **before**
measurement, which may itself initialize per-thread CRT state. It then installs
two independently specified triplets `(errno, _doserrno, last-error)`:
`(0,0,0)` and `(EDOM=33, ERROR_INVALID_PARAMETER=87, 0x20001234)`.
The last-error value uses the documented application bit. Call the accessor,
capture GetLastError immediately, then read the pre-resolved error cells through
volatile pointers. Capture both observations before formatting output or querying
mapping/module metadata. Restore saved error values after capture. Never read or
write the returned `_commode` object in this probe.

The frozen hypothesis is that each triplet is unchanged and both pointers agree.
Changes are preserved as **false hypotheses**, not rewritten, retried or hidden
behind an assertion demanding success. They would invalidate a preservation-based
candidate summary. Matching values only support these executions. The first
explicit probe call is not the runtime's first-ever call, because startup already
ran. No worker or concurrent mutation is added: earlier probes already measured a
joined worker, and more samples do not supply the missing effect proof.

`check_accessor.py` runs two fresh processes with a15-second bound and no retry,
retains raw output/exit/command/platform/timing and timeout diagnostics, source and
probe hashes, unchanged original binding, owner path, canonical file-handle path, checked x86 on-disk hash/version and
observed data-owner base. Linux parses the same downloaded evidence. These are
four observations from two processes, not four programs or native translations.
Six test functions cover literal expected records, changed values, malformed
records and conservative sticky negative composition using the pre-existing model.
No new cell implementation or proof issuer is introduced.

Reproduction in the existing MSVC x86 environment after compiler/CRT evidence:

```text
python research/crt/check_accessor.py EVIDENCE
python3 research/crt/check_accessor.py EVIDENCE --compare
python3 -m unittest discover -s research/crt -p test_accessor_evidence.py -v
```

## Provenance correction during artifact review

First candidate40de79c/CI40375232471 passed all five jobs and all four error
observations matched. Its probe reported `C:\Windows\System32\ucrtbase.dll`.
The 64-bit harness hashed that string without resolving the 32-bit process's
WOW64 redirection. That hash cannot be attributed to the mapped x86 owner. The
same limitation applies to earlier commode metadata collected with that protocol;
pointer/value observations remain observations, but those hashes are not evidence
of the loaded x86 implementation. The on-disk version alone does not repair this.

The corrected probe opens the reported module path inside its x86 process after
measurement and records GetFinalPathNameByHandle's canonical path, closing the
handle on every subsequent path. The harness hashes that resolved file and rejects
any PE Machine other than I386. The independent regression distinguishes a
synthetic x86 header from an x64 header and requires both original/canonical path
records. This fixes file-selection ambiguity; loaded-code equivalence and possible
file replacement still belong to the next proof gate. No redirection or security
setting is modified. Earlier successful CI is retained as historical evidence,
not substituted for final-head verification.

## Next finite gate: runtime-specific effect proof feasibility

Primary documentation plus more pointer/error samples cannot fill the missing
frame. The next authorized prerequisite is to determine whether a **specific
installed x86 runtime accessor's full effect graph** can be bounded and justified,
using an authored read-only analysis probe on the existing Windows CI runner.
No paid resource, installation, proprietary source import or security change is
needed for the initial feasibility check. Do not redistribute the runtime binary
or turn it into an executable test fixture.

Bind the actual resolved export/code owner, app-mode configuration, module version
and on-disk hash, observed load base and loaded-code identity; distinguish an import
thunk, forwarder and target. A data-owner address is insufficient. Analyze only a
small checked code window/graph in that owned test process, with explicit byte,
instruction and edge caps and no arbitrary process attachment. Prefer a local
analysis result and hashes over uploading proprietary code. Establish instruction
boundaries, every reachable branch/call/indirect target, memory reads/writes and
return behavior under stated preconditions. Unresolved TLS/OS helpers, indirect
targets, branches, faults or cap exhaustion produce a named no-go, not sampling.

Test any analysis logic against independently authored tiny routines with known
effects and adversarial targets. A single observed path is insufficient. If the
runtime is too complex or its required evidence cannot be obtained under existing
constraints, end that gate with the exact dependency and retain ordinary-CRT
rejection. Do not replace it with another synthetic owned-cell model. A proven
version-specific summary would still require review, caller precondition closure
and a production integration proposal; it would not generalize across runtime
updates. This gate warrants Astra High, followed by medium review.

All existing12 compiler comparisons,102 authored comparisons and18 launch checks
remain required; four held-out capabilities still reject. Four historical original
Windows timeouts remain unexplained, with existing failure diagnostics preserved.
Modern Windows Server2025 observations do not establish XP/7 or ordinary application
compatibility. No production eligibility, instruction or API support changes here.
