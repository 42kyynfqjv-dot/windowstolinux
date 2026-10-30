# Versioned second-fiber mapping and missing-export contract

The separately selected native extension
`w2l-native-second-fiber-20348-2398cc6a-v1` maps the observed
`api-ms-win-core-fibers-l1-1-2` and `kernelbase` names to the existing process-owned
KernelBase replacement provider. It creates an owned load reference through the
existing issuer and uses no parallel module or FLS registry. The older native
profile still rejects the new mapping until this extension is explicitly enabled.

On this declared target, GetProcAddress for exactly `FlsGetValue2` on that provider
returns null and LastError127, as independently observed. Other unimplemented
exports continue to reject, not return null. An unexpected descriptor for that
symbol contradicts the profile and rejects even when it is not callable. Module,
export, root, ABI, argument and resource checks precede the missing-result effect.
No function descriptor or callable authority is fabricated for an absent export.

## Windows evidence and scope

The original two-candidate observer, source and frozen configuration remain
unchanged in commit573d518. On Windows10.0.20348, both candidate loads succeeded,
both FlsGetValue2 lookups failed with error127, and both owned references released.
Its report lacked module identity and was insufficient for aliasing the handles.
[Version1 observations](evidence/second-fiber-windows-20348-v1.json) retain that limit.

A separate corrected version2 observer obtained the exact file-handle-resolved x86
module path for each successful load and hashed that file from the Python host.
Both mapped to `C:\Windows\SysWOW64\KernelBase.dll`, SHA256
`2398cc6ad909530545b4e4fbef7d7775447483431afdd90ab7306b8eed0a2ea1`.
Both again loaded, lacked FlsGetValue2/error127, and released their owned reference.
The source hash was checked against the new freeze. The original observer PE hash
was `ea7b050c1b877a1284cf957662a81ebe6a2115694acc4706c600f6bc43a4969e`;
compiler MSVC14.44.35207/hash and exact flags are in the retained report.

[Version2 observations](evidence/second-fiber-windows-20348-v2.json) come from
run41095617411/job124200454937/artifact12996845680, corrected source commit e169e4c.
The report was independently inspected in job logs; artifact binary/hash metadata
is reported by the observer and was not separately downloaded in this turn.
The intermediate e384d89 observer accidentally retained a second FreeLibrary;
review corrected it in e169e4c before using its identity report. Only the corrected
single-release source/hash is admission evidence. Intermediate CI/artifacts are
not deleted or substituted for the corrected observation.

This is an explicit target contract tied to this observed image revision. It is
not a claim about every20348 patch level, Windows11, XP/7, Wine, arbitrary API-set
mappings, or unknown DLL initialization. The native provider executes the existing
Rust initialization contract; Windows DLL entry points are not copied or executed.
Loaded and export-target authority retain their earlier lifetime rules. Successful
load LastError is left unknown; only the verified failed lookup supplies127.

## Connected original execution

With this extension, actual unchanged entry executes LoadLibraryExW at0x407f1d,
the module-cache XCHG at0x407eed and the GetProcAddress call at0x407efe. The real
owned module reference is retained in cache cell0x41ceac; the missing export returns
through original code. Entry next reaches indexed-lock CALL0x407e92→0x40bdcf and
rejects its unbound composition before lock acquisition or cache page mutation.

The earlier locks, process heap, cookie, FLS and read-only page remain live. The
function-cache word0x41e00c remains zero/read-only; the feature selector has not
returned, its caller's flag store has not executed, and the second FLS index is
still unallocated. Default admission remains blocked at0x402b00. This is an
instruction component checkpoint, not complete callback/startup/rcedit support.

## Independent tests and retained gaps

Twelve additional scenarios exercise enabled and unavailable profiles, invalid
profile selection, unknown names/flags, stale provider authority, reference-budget
failure, changed candidate/symbol bytes, unexpected export publication, invalidated
module authority after load, injected first-load failure followed by real second
candidate success, repeated alias load/reference release, and ABI corruption.

Expected partial boundaries are exact, and previous effects are asserted: successful
load remains owned when lookup rejects; invalidation before cache publication
preserves the acquired reference but publishes no stale module; injected first-load
failure retains that candidate's failure sentinel before the next load/lookup;
bad ABI leaves prior LastError intact. Matching native releases consume only the
owned acquisitions, preserve the process root and reject replay/destruction while
borrowed. These injected failures are conformance inputs, not measured Windows
resource-exhaustion outcomes. Existing fifteen FLS and prior ownership tests remain.

Next integrate logical lock14 with its actual owned object slot, protected function
cache write/read-only restoration, matching release and failure ordering, then the
original PTD/FLS acquisition context. The bootstrap lock means logical index14 is
not native tracking slot14. Those effects remain rejected here. Sol can review
and implement this normalization; no new Astra-only semantic question has yet
been demonstrated. Nonnull teardown and actual exception-delivery contracts stay
unproved. Historical original-Windows timeout causes remain unresolved.

Local verification: 286 CRT tests passed; both artifact tests passed in the
reviewed replay; 76 Python tests passed with one existing skip; all seven guard
mutants and ten frame vectors passed; Clippy and formatting passed.
[Source/artifact/test hashes](evidence/second-fiber-profile.json). New-head CI is
a separate pending gate; corrected observer success is not full regression success.
