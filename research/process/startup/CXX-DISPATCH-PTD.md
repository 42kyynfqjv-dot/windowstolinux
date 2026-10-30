# C++ dispatcher PTD is a distinct runtime object

This component advances the original C++ path after context validation. It does
not admit whole startup, rcedit, original Windows delivery, or arbitrary C++
exceptions. It imports no proprietary runtime source. Requirements below derive
from the unchanged authored PE and independently specified native input cases.

## Original evidence

Dispatcher403d85 calls4028c3. That wrapper calls4028d1, tests EAX and branches to
termination4077ff if null. Getter4028d1 uses module index41c060, saves LastError,
invokes402bb4, treats -1 as null, and restores LastError on its returning paths.
The null path sets an initializing sentinel, allocates40 bytes, installs the
result, and frees an uninstalled allocation. Those setter/allocation/free calls
remain unbound and reject at their actual call sites with prior effects intact.

Resolver wrapper402bb4 calls402a53, then invokes a guarded dynamic function or
its kernel32!TlsGetValue fallback at415060. Setter402bef similarly falls back to
TlsSetValue at415064. Resolver selection, TLS index generation/lifetime, thread
acquisition, callback exceptions and lazy effects remain unproved. The explicit
lookup callback in this component must not be described as executing them.

This is distinct from UCRT getter40a332, module index41c170 and FlsGetValue import
4150a0. A UCRT errno-prefix capability of20 bytes cannot authorize access to this
VCRUNTIME object's offset0x20. Its40-byte allocation is observed in original
instructions, not inferred from an API name or a zero-initialized fixture.

## Connected execution and supported boundary

Shared structural IR lifts the complete original146-byte getter and14-byte
required-object wrapper. The latter's certified conditional termination edge is
an explicit rejecting exit; the generic decoder's policy is unchanged. No null
exit can become successful cleanup or RET.

The getter invokes a protected callable boundary at402bb4. Independent test
callbacks supply a lookup result/effects; they do not establish a slot in Windows
or the earlier UCRT FLS model. The required-object return validates an exact live
ThreadData root of at least40 bytes. It rejects interior/narrow aliases, scalar
addresses, wrong kind, stale or foreign capabilities and truncated ranges before
granting a successful protected return. The next21 original dispatcher bytes
then execute through CMP [EAX+0x20],ESI. The accessed word must be initialized;
other bytes remain unknown. No object field is silently filled with zero.

LastError follows the original getter: it is restored after returning lookup
paths, including later extent rejection. A lookup error, unknown result or null
path rejected at a lazy call preserves effects already performed; restoration is
not fabricated after a call that never returns. Unknown LastError remains unknown.

## Independent checks

Two Rust test functions compile native component code. Fourteen PTD cases cover
40-byte success,20/39-byte truncation, interior/scalar/unknown/wrong-kind results,
null, -1, invalid index, unknown LastError, retired and cross-runtime results,
lookup failure after a visible write, protected-return replay and exact error
restoration. All getter/wrapper byte mutations reject. Nine connected handler
cases retain context/frame/guard corruption coverage and include an unknown
PTD+0x20 read. Existing captured-context/stack/lifetime tests remain enabled.

The artifact checker binds both original functions and the dispatcher field-use
bytes, and verifies actual TLS fallback import identity. Existing five recorded
Windows wrapper comparisons remain separate. There are zero new original-Windows
observations or whole-PE translation pairs.

## Next connected gate

The path now rejects before dispatcher branch403d9f/table traversal. Bind the
resolver402a53 and dynamically selected TLS/FLS backend contract with runtime
instance, index/thread identity, lifetime and exception effects; do not reuse the
unrelated UCRT FLS slot. Then execute exception-code/flag and metadata branches
from the actual dispatcher, retaining unknown-state rejection. Both metadata
unwind entries still select a PTD-dependent termination path; no cleanup receipt,
disposition or restoration authority follows from the current component.

## Cached fallback and connected dispatcher checkpoint

Original lookup wrapper402bb4 and resolver cached fast path402a53 now execute.
The live module table entry at41cd1c supplies backend selection for original
argument2. A known -1 cached failure returns null from the resolver, so original
wrapper instructions choose kernel32!TlsGetValue. The protected API callback now
has the actual stdcall argument/RET4 contract. Module range/kind, initialized
cache contents and exact selector identity are checked. Cache zero enters cold
resolution and rejects; nonzero dynamic pointers reject without invocation.

The original requested dynamic symbol at415d54 is `FlsGetValue`. Thus the dynamic
route is FLS and the fallback is TLS; neither can share state simply because the
functions return pointer values. This checkpoint proves cached fallback selection
under explicit live module inputs. It does not acquire a Windows TLS slot, execute
cold module loading/GetProcAddress, or prove dynamic FLS callback identity/lifetime.
The backend callback remains the explicit API-state/effect cut.

After a valid PTD result, original dispatcher217-byte tail now executes and the
common wrapper's original epilog returns. Metadata scalar address annotation is
promoted to an already checked live module capability only after exact address
and complete metadata revalidation. The exception argument must be a live Context
object covering80 bytes; unknown fields reject when read. Two separately supplied
non-unwind exception cases (C++ code and unrelated code) return numeric disposition1
through original branches and protected RET. This completes a normal callback
return, not guest exception resumption. All original calls for local unwind,
search or guarded dynamic handlers remain rejecting effects.

Tests now cover19 PTD/backend cases and11 connected handler scenarios. New cases
include cold/dynamic/unknown cache, truncated/wrong-role cache storage, the two
normal dispositions and an unwind request rejected at the original call. Full
wrapper/resolver/tail byte mutations reject; original eight-argument forwarding
checks remain active. Actual TLS state acquisition, cold resolver effects,
dynamic FLS ownership, local unwind/termination and whole startup remain open.
