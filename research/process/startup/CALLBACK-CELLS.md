# Original startup callback cells

The explicit controlled native-profile entry executes the original getters and
live NULL decisions from **0x4016ba through 0x4016ff**, reaching **before
CALL0x401700 →0x406c88**, the environment-vector getter. Both empty and three-entry
synthetic environment variants are required. The original normal frame, scope0,
startup state2 and process-owned filter remain live. This is component execution
from the unchanged entry instructions, not admission of a complete translated PE.

## Producer and instruction provenance

The original six-byte getters at0x401c2b and0x401c31 return addresses0x41d2f8 and
0x41d2f4. They do not read the words and do not produce callback values. In the
frozen authored PE, `.data` starts at RVA0x1c000, has raw size0xa00 and virtual
size0x1304. Both words are in its virtual zero-filled tail. The TLS directory is
absent (RVA/size0/0); whole-image disassembly has no other direct reference to
either word. This static inventory alone does not prove absence of indirect writes.

The existing mapper supplies initialized zero bytes for the virtual tail. No
callback-specific initialization is added. All earlier admitted startup bodies
still execute with their existing bounded write and API contracts. The final
entry test checks the live cells after those effects, then the original CMPs
read them again at their actual instruction points. A changed cell, unknown byte,
opaque alias, expired mapping or unreadable page does not inherit the initial
zero as a cached fact. Getters/caller bytes are checked against live executable
storage; the replay additionally compares all three regions with the same PE.

MOV/RET produce raw address bits. Only the following owned image load binds ESI
to the exact canonical cell. No integer is promoted into callback authority.
Both actual protected getter returns execute, then the original ESI/EDI moves,
CMPs and conditional branches execute. EAX ends as0x41d2f4, ESI as its canonical
cell pointer and EDI as known zero. ECX retains the earlier byte-initialized
release argument, including unknown upper bits. LastError knowledge is unchanged.
The declared profile admits no concurrent guest or asynchronous slot mutation.

## Non-NULL cells and rejection ordering

A non-NULL value follows the original PUSH ESI and CALL0x401a05. The call owns a
protected child return, then rejects **before the unsupported validator body**.
The cell is not eagerly converted to a code pointer, treated as NULL, or invoked.
The caller's push and call effects survive rejection. The rejected component
path grants no callback/continuation receipt and cannot resume application code.
This rejection is an unsupported boundary, not an emulated Windows disposition.

Original0x401a05 uses EH4 registration and checks live DOS/PE32 headers, calls
section finder0x4018d1, and tests bit31 of the containing section's Characteristics
field. Its argument is the **cell address**, not the callback value. It has an
access-violation filter/landing path. Current VirtualProtect page permissions
are not a replacement for this PE section test. The true branch reloads the
first target only after validation, executes the CFG guard and calls it with
three arguments; the second true branch registers a destructor at0x40701a.
Neither branch, the validator's exceptional path, nor callback execution is
admitted by this change. Mutating an unexecuted true-branch byte rejects under
the existing conservative whole-region code certificate.

## Independent review and checks

Review of929d9be found no additional defect in flag-guard ordering, byte-only CMP,
known-scalar initialization-exclusive XCHG, protected returns or earlier effects
on a later rejection. Independently rehashed all567 predecessor source blobs and
the completed report f3af6d17b72e5cac5456274838b4926092f80ecaea0f03d3a5c1b5d3c5d44a5e.
All three exact-head workflows **41393614264 /41393608622 /41393608615 passed**.
Five Windows component comparisons remain distinct from whole-PE execution.

Twenty-one native cases exercise both mapped NULL words, nonzero numeric and
owned-pointer values, unknown/partially known values, truth-only nonzero values,
read-only/read-protected/opaque cells, stale initialization/thread/image,
duplicate return authority, malformed getter ABI, getter/caller/unused-branch
mutations and preservation of original call/push/register/LastError effects.
Every success and failure has a strict expected result. Existing32 release,
27 caller and all152 word cases remain required; the latter keep the512KiB
child limit and64KiB environment padding. Canonical/aggregate/Python/Clippy and
final clean commit-pinned replay are separate gates. Local validation passed362
CRT tests (two artifact gates separate),185 unwind tests, the canonical variants,
115 Python tests (one skip), Clippy with warnings denied, formatting and all152
low-stack cases. Read the current tracker
and replay metadata for final outcomes, not this implementation inventory.

## Next connected scope

The original environment getter0x406c88 reads0x41ce54 and returns it if nonzero;
otherwise it calls the original producer0x4069df and stores the result. That
producer reads0x41ce48 and may enter existing initialization/copy dependencies.
Then original0x4070b2/0x4070ac return argv/argc cell addresses0x41ce6c/0x41ce68.
The caller loads argv and argc, pushes envp/argv/argc and reaches Main CALL0x401717.
Bind these to the already executed canonical producers and live owned storage,
with stale/unknown/reentry/failure and mutation cases; do not synthesize vectors
or bypass the fallback path. This is a bounded Sol integration scope. Supporting
non-NULL callback cells separately requires the actual normal EH4/header walk,
valid bounded live-header evidence and explicit exceptional-path rejection or
proved delivery; raw page permission or a precomputed boolean is insufficient.

Full startup/default/rcedit admission, nonzero-flag TEB/CAS lock acquisition,
concurrency, exceptional delivery and resource-failure equivalence remain unproved.
Historical C01/case19 and other original-Windows timeouts remain unresolved;
output, WCT and subsequent passing CI do not locate the stalled instruction or
stack. No retained evidence, timeout, comparison or ownership gate was removed.
