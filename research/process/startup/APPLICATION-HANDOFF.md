# Application entry ownership and original Inner prefix

The explicit native profile reaches original Main CALL0x401717 after the original
startup state2 publication and argument pushes. This boundary revokes constructor
permission while preserving the actual startup frame. Main, Outer and Inner then
use a separate application instruction lease. The original entry now executes RaiseException CALL0x401117 through the
[producer-bound suspension contract](PENDING-CALL.md), then stops before delivery. This is
component execution from the original entry, with zero whole-PE exit comparisons.

## Handoff

The issuer checks the actual active caller, live frame image and protected return,
registry/epoch identity, sole installed normal frame, unchanged predecessor,
complete saved fields, no consumed epilog slots, no delivery or C++ child, live
image/fiber and generation space. The original caller additionally checks scope0,
startup state2, exact CALL bytes and argument-stack position. Shared CALL preflight
checks return-slot range, permissions, protected aliases and identity space before
the handoff. No original instruction is replaced by a success callback.

Pending provider builds and every lock lease block revocation. All fallible checks
precede mutation. The final transition clears initialization, installs a fresh
runtime-owned application lease and updates the parent's binding together. It
writes no guest bytes or CPU bits. Old initialization tokens immediately reject;
reentry cannot replay the transition. Later CALL/prolog failures retain earlier
original stores and the completed transition, without certifying completion.

The application lease binds runtime arena, process/thread, current fiber, main
image and generation. Every original Main/Outer/Inner instruction wrapper validates
it; frame bindings separately retain registry/epoch, actual stack and protected
return ownership. Changing/retiring those owners invalidates the lease/binding.
Main's shared original memset accepts the same checked image interface. This
interface cannot grant constructor permission. Existing initialization components
retain their old token checks. Canonical post-run descriptor inspection now takes
real record leases because the startup-exclusive permission has expired.

The handoff deliberately happens before Main. At that point there is only one
live startup frame to transfer. No saved snapshots or reconstructed ancestor
CPUs are needed to convert a nested live chain later. Original CALLs create the
Main, Outer and Inner ownership chain under normal execution authority.

## Inner instructions and absence of saved ESP

The unchanged Inner prolog0x4010c0..0x4010ef publishes FS at0x4010ea. The shared
symbolic frame proof derives the finally-only shape and proves no memory store
from ESP across the entire call-free prolog. Its saved-SP layout is None, exactly
as Outer; Main still has its actual delayed saved-SP MOV. No uninitialized word
is read or promoted to a restoration pointer.

Original stores set local100, cursor0, scope0 then scope1. Four original PUSHes
write arguments [0xe0424242,0,0,0]. Scope/header/caller/prolog/epilog/body bytes are
checked against the unchanged PE and live image. The original epilog supplies a
frame reservation plan only; return and cleanup have not executed on this path.

## Validation and limits

Tests exercise successful transfer, stale init/thread/image/return/guard/fiber,
incomplete saved fields, generation exhaustion, unpublished provider and live-lock
rejection, replay, and expired application authority. Success requires preserved
CPU bits, memory tags and chain. Inner code/scope mutants reject after the correct
prior caller effects. Both empty and three-entry synthetic environments reach the
same live four-frame chain through original startup. No real environment data is
recorded. The final replay verifies source hashes, original bytes and retained
five Windows component comparisons; it adds no Windows acquisition observations.

This does not enable normal-phase heap/FLS/FP/constructor APIs by weakening their
initialization checks. Canonical resources and their identities remain stored;
normal API effects need their own justified operation permits. The generic absent-SP
pending issuer remains rejected; a separate original producer now permits CALL
suspension without manufacturing a saved-SP field or Windows CONTEXT. Delivery
and containment still need proof before resumption. Main/Outer/Inner returns,
exceptional cleanup, resource failure equivalence, default admission and full
startup/rcedit remain unproved.

Predecessor e8446af PR and inventory CI passed. Its push workflow failed original
Windows case28 before conversion (run41419216825/job125190443685), and Linux passed.
Case28, historical C01 and case26 causes remain unresolved; later passes are not
diagnoses. See SUB-579 for this commit's exact CI and final replay hashes. Earlier
local harness failures (missing evidence directory, protected-corruption injection,
fixture stop marker, and unleased post-handoff descriptor inspection) remain in
local logs; their corrections do not loosen runtime checks.
