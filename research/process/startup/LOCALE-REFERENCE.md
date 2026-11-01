# Original multibyte reference helper

The explicit native entry executes original CALL `0x40b25a -> 0x40b38a` and
returns to `0x40b25f`. It rejects there, before the next original argument push
and code-page selector call at `0x40b262 -> 0x40afbc`. The initialized flag remains
zero. This is connected component execution; full startup/rcedit/default admission,
aligned exception unwinding and native close/EOF equivalence remain unproved.

The helper binds its complete original bytes, shared EH4 prolog, scope table
`0x41b660`, registered frame and normal epilog. Its UCRT argument must be the
same live 868-byte allocation published in current-fiber FLS. It executes original
reads, branches, lock5 acquisition/release, reference stores and normal return.
The null-result termination call remains an explicit rejection. The free call
remains unbound: a decrement already performed before reaching that call stays
visible, with the frame and lock retained rather than falsely completed.

Shared `LOCK XADD m32,r32` decoding requires a consumer-bound memory effect.
Default emission rejects it. Under the supported single-guest-thread/exclusive
lease contract, the runtime checks initialization, image identity, lock lifetime,
alignment, permissions and complete scalar knowledge before the indivisible
read/write. The source register receives the old word; flags describe the original
sum modulo 2^32. No callback/interleaving occurs between read and write. This is
not a claim of general concurrent Windows atomic memory semantics or arbitrary
heap-reference support. Unsupported heap targets reject instead of being retagged.

Independent conformance covers six arithmetic boundary vectors, old-value results,
CF/ZF/SF/OF, preserved other registers, unknown addends, misaligned words and stale
locks. Twenty-five declared locale scenarios include changed helper bytes,
fast and locked paths, reference replacement, null termination and decrement
preservation at the free rejection. Their constructed reference inputs remain
separate from the original entry's actual producers and from Windows observations.
The artifact harness binds the helper bytes directly against the unchanged PE.

Review of predecessor `13334bf` found no new defect in aligned AND, actual CALL
continuations, scalar mirrors, failed-child invalidation, EBX/original RET storage
or Main's clearing of unrelated continuation knowledge. Its existing adversarial
cases are retained. CI outcomes must be read by exact head; a local pass does not
assert cross-host CI success.

Next: execute the original code-page caller/selector with checked CP producers.
The actual callback selects -3, requiring GetACP to match the declared native
65001 profile; Windows ACP is not universally UTF-8. Preserve locale lifetime,
partial effects and original errors. Heap reference freeing and exceptional EH4
cleanup require separate complete ownership/effect proofs before admission.
Historical Windows case19 timeout remains unresolved; passing retries do not
diagnose it. [Earlier aligned contract](LOCALE-STARTUP.md) and
[dependency map](DEPENDENCIES.md) preserve preceding scope and evidence.
