# Original code-page selector and declared native ACP

The explicit native entry executes the original argument push and
`CALL 0x40b262 -> 0x40afbc`, including its locale-view constructor at `0x40aabe`.
The actual callback selects `-3`; original code calls named import
`kernel32!GetACP` at `0x40affe`, returns `65001`, and reaches `0x40b267`.
Replay rejects before that continuation's first instruction. The initialized
byte at `0x41d148` stays zero. This is connected component execution with the
existing explicit launch/registry premises, **not whole-PE translation**.

## Encoding and authority

The native GetACP adapter uses the same live process token as the A/W command
line buffers. That token was produced by the explicitly selected UTF-8 launch
profile; ordinary entry obtains it from actual Linux argv acquisition. It checks
process/runtime identity, both buffer lifetimes and immutable initialized storage,
the API ABI and writable protected return before completing the original call.
It cannot derive a code page from unknown guest registers or a stale/foreign token.
LastError and volatile registers/flags become unknown where not promised.
The adapter binds this checked named import; it does not publish a dynamic
GetProcAddress descriptor or authorize an arbitrary indirect target.

Requiring both command-line buffers to remain live is an internal conservative
admission condition, not a claim that Windows GetACP reads those buffers.
There is no assertion that Windows ACP is universally UTF-8, or that a Linux argv
snapshot recovers an arbitrary original Windows raw command line. The previously
frozen UTF-8-manifest Windows observer measured GetACP65001 on Windows20348;
its Unicode/quoting observations remain API/CRT conformance, not translated pairs.
That manifest observer does not establish the unchanged `unwind.exe` target's
Windows launch ACP. The selected native encoding is an explicit component premise,
not a certificate of equivalence to the target's default Windows environment.

Primary contracts:

- [GetACP](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getacp)
  returns the current Windows ANSI code-page identifier and warns it varies.
- [UTF-8 process code pages](https://learn.microsoft.com/en-us/windows/apps/design/globalizing/use-utf8-code-page)
  documents the explicit manifest policy from Windows1903 onward. This does not
  establish XP/7 behavior. No host configuration changes are performed here.

## Original paths and effects

Complete unchanged selector and constructor byte ranges are checked against the
mapped authored PE. Shared normalized lifting/emission executes their actual
reads, branches, stores, stack operations and returns. The ordinary global-locale
branch copies existing locale references; it never invents their initialization.
An explicit locale pair may also be read under checked pointer ownership.

Explicit numeric arguments are returned as the original selector requires;
that result does not authorize encoding conversion for that code page. The `-4`
case reads the checked mapped locale's code-page word. OEM selection and the
constructor's per-thread mutation helpers are explicit unsupported calls. Prior
flag and data writes remain visible on rejection. The locale-view's untouched
PTD field remains unknown when the original path never initializes it.

Tests require exact results for four successful selector branches and exact
errors for fourteen rejected branches, plus repeat/replay checks. Four independent
constructor cases cover provided locale pairs, stale input/output and an output
alias into the protected return. Twenty-nine existing entry/getter/reference
cases now include caller/selector/constructor mutations and missing profile;
these declared component inputs are separate from the actual entry producer path.

Review of `1a08b95` checked LOCK XADD old value, wrap/flags, pre-write validation,
exclusive lease and preservation of the decrement at rejected free. All three
exact-head workflows passed. Its later completed replay retained five recorded
Windows wrapper component comparisons; no whole-PE evidence followed.
The review also independently decoded all ten binary CMD1 outputs in its Windows
command-line artifact13068170083 (run41266822324/job124731240052), checked archived
source/manifest/vector bytes against the repository and verified PE/output hashes.
These are ten rerun frozen cases, not ten new cases or translated pairs.

## Next connected executable work

At `0x40b267` original code loads the UCRT argument, discards twelve argument
bytes, stores the selected code page locally and compares it to the current
multibyte reference's code-page word. A differing code page reaches
`CALL 0x40b284 -> 0x408730`, requesting `0x220` bytes. Bind the canonical reference
view and original allocation/initialization flow without manufacturing initialized
bytes. The original allocator calls HeapAlloc with flags0 (uninitialized), whereas
the existing bounded native allocation contract accepts flags8 (zeroed). Reusing
calloc's zeroing would change observable initialization; preserve failure/retry,
new-handler and original errno paths as well. The subsequent copies,
GetCPInfo/validation, publication and reference
release need their actual effects before the initializer flag can be set.

Sol can continue that bounded caller/allocator inventory; no new hard stack
ownership design is established by this slice. Escalate only a demonstrated
ownership or lifetime ambiguity. Heap-reference freeing, exceptional EH4 cleanup,
general concurrent atomics, native close/EOF, Windows delivery/collided unwind,
full formatter/startup/rcedit/default admission remain separate unproved gates.
Historical Windows case19 timeout and other retained failures remain unresolved.

See [dependency map](DEPENDENCIES.md), [current evidence](evidence/locale-code-page.json),
[previous helper](LOCALE-REFERENCE.md), and [Windows input provenance](COMMAND-LINE.md).
