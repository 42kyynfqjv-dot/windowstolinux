# Named native export lookup and original cache publication

The explicit `w2l-native-sync-20348-v1` component profile now binds the original
GetProcAddress CALL402ae0/IAT415070. It reads the actual checked module argument
and terminated ASCII export name, requires the profile's source identity, and
returns the unique already implemented `CrtFunction`. The adapter executes the
checked stdcall RET8. Lookup creates no descriptor, reference or callable issuer.

The shared lookup checks process/initialization ownership, live provider root,
unique case-sensitive name, complete provider export-index membership, callable
implementation identity and separately live actual export target. Forwarded
source/target ownership is supported by the shared lookup; this profile still
permits only its declared same-provider synchronization mapping. Unknown names,
ambiguous exports, ordinal/scalar arguments, incomplete publication, unimplemented
exports and stale source/target reject. These rejections are internal unsupported
contracts, not invented Windows NULL/GetLastError outcomes.

The unchanged resolver executes its real TEST, XCHG402aef and RET after lookup.
On the authored input, function index4 publishes to41cd24; module index1 remains
at41cd0c. Constructor-prefix execution ends at402c47 before its remaining MOV,
argument cleanup, guard and indirect invocation. This boundary now reports
`startup constructor body unbound at 0x402c47` explicitly, rather than letting a
fragment fall into the callee's missing-RET check. No lock initialization or
successful constructor return is implied. Default admission still rejects the
LoadLibraryExW boundary402b00.

Independent tests exercise 12 source/target cases including actual callable lock
construction after lookup, missing and differently cased names, duplicate names,
unimplemented/removed descriptors, incomplete publication, uncertain source and
forwarded target, wrong thread, teardown and reused handles. The original-entry
negative mutates only the readonly export-name bytes to request a missing symbol:
the acquired module/cache survive, function cache remains zero, and execution
rejects before publication. Existing changed-code, stale-provider, capacity and
readonly-storage cases remain mandatory. These are component tests, not new
Windows or whole-PE execution pairs.

Review of4a7ec01 retained its profile restrictions and root/ref lifetime checks.
The fixed reference table's three insertion callers preflight capacity and serial
bounds; sparse-slot iteration changes no reference-set comparison semantics.
Its allocator-denied transport test remains required. The profile still requires
bootstrap resource availability and later whole-program budget proof. No Windows
version equivalence follows solely from choosing the profile name.

Next lift the complete original constructor tail402c47..402c73, prove pointer/index
and argument extent for the dynamic synchronization call, bind the actual guard
and preserve the fallback path. Keep InitializeCriticalSectionEx resource/failure
semantics gated; a lookup success does not establish that later API success.
Sol can handle this bounded integration/review; escalate a demonstrated ownership
or resource-contract uncertainty. Full startup/rcedit and historical Windows
timeout causes remain unresolved. PR45 remains draft.

Reproduction and hashes: [evidence/named-native-export.json](evidence/named-native-export.json).

Local validation passed279 CRT tests (two artifact tests exercised separately),
12 independent lookup scenarios, Clippy and formatting. The first new mutation
test assumed one textual occurrence and then used a fixed length excluding NUL;
both failed assertions are retained under the local named-export evidence folder.
The corrected test derives the intended RVA from PE sections and bounds its
comparison with the literal length. It passes without changing original fixtures
or runtime outcomes. Five recorded wrapper comparisons are retained component
measurements; there are zero fresh Windows observations or new whole-PE pairs.
