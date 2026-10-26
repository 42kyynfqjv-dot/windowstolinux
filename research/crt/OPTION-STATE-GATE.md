# Next executable work: bounded callback10e0 ownership contract

SUB-540 medium review confirms original table identities and27 call bindings plus
independent Windows ABCD/0 and A/7 observations. It corrects a model composition gap:
a blocked state must remain blocked across dispatch calls, so later known writes
cannot reestablish callback-slot zero after unknown external mutation. The existing
unknown-effect test now exercises this sequence. Exact-profile inventory now rejects
missing disassembly call lines instead of silently reporting a smaller call set.

Next Astra High work is a test-only owned-data effect implementation for the exact
callback10e0, helper1770 and accessors1750/1760. No whole-startup replacement. Bind
one owned PE snapshot, callback table relocation, complete instruction forms, helper
call edges, accessor HIGHLOW operand provenance and two distinct writable initialized
8-byte regions (snapshot RVAs30d0 and30d8). Reject changed targets/bytes, prefixes,
metadata/header/code/zero-fill/partial ranges, overlapping regions, relocation sites
inside data, protected callback/return/cookie/onexit-state overlap and unresolved aliases.
Addresses may vary only if all provenance and region checks are repeated.

Model bytes, initialization and ownership for the full ranges before any effect.
Little-endian low dword1 becomes old|0x24; low dword2 becomes old|0x02. Adjacent high dwords
are read then written back unchanged; do not erase those reads/writes or grant access
to uninitialized high bytes. EAX returns0 from callback10e0; final tracked CF/OF=0,
ZF=1,SF=0 come from its XOR EAX,EAX. OR and intervening MOV/CALL/RET flag effects must
be accounted for, including unspecified flags if later observable. Valid incoming
stack/call returns and no-fault/no asynchronous mutation remain explicit assumptions.
No other register/global/API authority is inferred. State already blocked by an
unknown prior effect cannot yield a successful composed startup certificate.

Acceptance: independently authored byte layouts and boundary cases for0/all-one/
nonzero high words, exact changed-byte footprint, both regions validated before
writes, high-word initialization, alias/protected/bounds negatives and unchanged
state on rejection. Compare concrete model results with a separately authored C
operation probe or CPU fixture, labelled separately from unchanged-program translation.
Reproduce exact original helper/table/address provenance from CI artifacts; document
failure if compiler layout changes. Do not hand-edit original binaries. Run existing
79 Rust functions/eight initializer models, graph checks,12 compiler102 authored18
launch evidence. Ordinary CRT and four held-out cases remain rejected. Then medium
review before any production effect support. No merge/release or new paid/security
resources.1030/10f0 external effects remain separate unresolved obligations.
