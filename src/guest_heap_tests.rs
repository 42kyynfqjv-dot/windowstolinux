use super::*;
const YES: Availability = Availability::Available;
fn space() -> Space {
    Space::new(1024, 16).unwrap()
}
fn allocation(s: &mut Space, size: u32, flags: u32) -> u32 {
    s.heap_alloc(s.process_heap(), flags, size, YES)
        .unwrap()
        .unwrap()
}
#[test]
fn heap_identity_and_numeric_alignment() {
    let mut a = space();
    let mut b = space();
    let h = a.process_heap();
    assert_eq!(h, a.process_heap());
    assert_ne!(h, b.process_heap());
    assert_eq!(
        b.heap_alloc(h, 0, 8, YES),
        Err(HeapError::Memory(Fault::Identity))
    );
    for n in [1, 3, 8, 9, 31] {
        let p = allocation(&mut a, n, 8);
        assert_ne!(p, 0);
        assert_eq!(p % 8, 0);
    }
    let p = allocation(&mut b, 8, 8);
    assert_eq!(
        a.heap_free(b.process_heap(), 0, p),
        Err(HeapError::Memory(Fault::Identity))
    );
}
#[test]
fn heap_zeroing_and_unknown_bytes_are_distinct() {
    let mut s = space();
    let p = allocation(&mut s, 7, 0);
    let q = allocation(&mut s, 7, 8);
    assert_eq!(s.read(p, 1), Err(Fault::Uninitialized));
    assert_eq!(s.read(q, 7).unwrap(), &[0; 7]);
    s.write(p + 2, &[0x12, 0x34, 0x56]).unwrap();
    assert_eq!(s.read(p + 2, 3).unwrap(), &[0x12, 0x34, 0x56]);
    assert_eq!(s.read(p + 1, 4), Err(Fault::Uninitialized));
    assert_eq!(s.read(p + 7, 1), Err(Fault::Range)); // padding is not requested storage
}
#[test]
fn heap_reallocation_preserves_partial_prefix_and_only_zeros_new_tail() {
    let mut s = space();
    let h = s.process_heap();
    let p = allocation(&mut s, 4, 0);
    s.write(p, &[0xde, 0xad]).unwrap();
    let old = s.heap_capability(h, p).unwrap();
    let fact = s.prove_read(old, PROCESS_HEAP_OWNER, p, 2).unwrap();
    let q = s.heap_realloc(h, 8, p, 9, YES).unwrap().unwrap();
    assert_eq!(q, p);
    assert_eq!(s.validate(old, PROCESS_HEAP_OWNER), Err(Fault::Stale));
    assert_eq!(s.read(q, 2).unwrap(), &[0xde, 0xad]);
    assert_eq!(s.read(q + 2, 2), Err(Fault::Uninitialized));
    assert_eq!(s.read(q + 4, 5).unwrap(), &[0; 5]);
    assert_eq!(s.read_proven(fact, PROCESS_HEAP_OWNER), Err(Fault::Stale));
    let r = s.heap_realloc(h, 0, q, 1, YES).unwrap().unwrap();
    assert_eq!(s.read(r, 1).unwrap(), &[0xde]);
    assert_eq!(s.read(r + 1, 1), Err(Fault::Range));
    let r = s.heap_realloc(h, 0, r, 3, YES).unwrap().unwrap();
    assert_eq!(s.read(r + 1, 1), Err(Fault::Uninitialized));
}
#[test]
fn heap_move_keeps_neighbors_and_invalidates_old_capability() {
    let mut s = space();
    let h = s.process_heap();
    let p = allocation(&mut s, 8, 8);
    let blocker = allocation(&mut s, 8, 8);
    s.write(p, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    s.write(blocker, &[9; 8]).unwrap();
    let cap = s.heap_capability(h, p).unwrap();
    let q = s.heap_realloc(h, 8, p, 24, YES).unwrap().unwrap();
    assert_ne!(p, q);
    assert_eq!(s.read(q, 8).unwrap(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(s.read(q + 8, 16).unwrap(), &[0; 16]);
    assert_eq!(s.read(blocker, 8).unwrap(), &[9; 8]);
    assert_eq!(s.read(p, 1), Err(Fault::Range));
    assert_eq!(s.validate(cap, PROCESS_HEAP_OWNER), Err(Fault::Stale));
}
#[test]
fn heap_failure_preserves_allocation_and_existing_read_facts() {
    let mut s = Space::new(16, 1).unwrap();
    let h = s.process_heap();
    let p = allocation(&mut s, 8, 8);
    s.write(p, &[0x42]).unwrap();
    let cap = s.heap_capability(h, p).unwrap();
    let fact = s.prove_read(cap, PROCESS_HEAP_OWNER, p, 1).unwrap();
    assert_eq!(
        s.heap_realloc(h, 8, p, 16, Availability::AllocationFailed),
        Ok(None)
    );
    assert_eq!(
        s.heap_realloc(h, 8, p, 17, YES),
        Err(HeapError::Memory(Fault::Budget))
    );
    assert_eq!(
        s.heap_alloc(h, 8, 8, YES),
        Err(HeapError::Memory(Fault::Budget))
    );
    assert_eq!(s.read_proven(fact, PROCESS_HEAP_OWNER).unwrap(), &[0x42]);
    // Final logical size fits even though old+replacement exceeds 16 bytes.
    assert_eq!(s.heap_realloc(h, 8, p, 16, YES), Ok(Some(p)));
    assert_eq!(
        s.heap_alloc(h, 0, 1, Availability::AllocationFailed),
        Ok(None)
    );
}
#[test]
fn heap_free_and_numeric_reuse_do_not_reuse_proof_identity() {
    let mut s = space();
    let h = s.process_heap();
    let p = allocation(&mut s, 8, 8);
    let cap = s.heap_capability(h, p).unwrap();
    s.heap_free(h, 0, p).unwrap();
    assert_eq!(s.heap_free(h, 0, p), Err(HeapError::InvalidPointer));
    let q = allocation(&mut s, 8, 8);
    assert_eq!(q, p);
    s.write(q, &[77]).unwrap();
    assert_eq!(s.read(p, 1).unwrap(), &[77]);
    assert_eq!(s.validate(cap, PROCESS_HEAP_OWNER), Err(Fault::Stale));
    // Raw old bits now identify the new object, just as numeric machine addresses do.
    s.heap_free(h, 0, p).unwrap();
}
#[test]
fn heap_rejects_unreviewed_flags_sizes_and_invalid_bases_without_mutation() {
    let mut s = space();
    let h = s.process_heap();
    let p = allocation(&mut s, 8, 8);
    for flags in [1, 4, 16, 9, 24, u32::MAX] {
        assert_eq!(
            s.heap_alloc(h, flags, 8, YES),
            Err(HeapError::UnsupportedFlags)
        );
        assert_eq!(
            s.heap_realloc(h, flags, p, 8, YES),
            Err(HeapError::UnsupportedFlags)
        );
        assert_eq!(s.heap_free(h, flags, p), Err(HeapError::UnsupportedFlags));
    }
    assert_eq!(s.heap_alloc(h, 0, 0, YES), Err(HeapError::UnsupportedSize));
    assert_eq!(
        s.heap_realloc(h, 0, p, 0, YES),
        Err(HeapError::UnsupportedSize)
    );
    for bad in [0, p + 1, p + 8, u32::MAX] {
        assert_eq!(s.heap_free(h, 0, bad), Err(HeapError::InvalidPointer));
        assert_eq!(
            s.heap_realloc(h, 0, bad, 8, Availability::AllocationFailed),
            Err(HeapError::InvalidPointer)
        );
    }
    assert_eq!(s.read(p, 8).unwrap(), &[0; 8]);
}
#[test]
fn heap_placement_respects_module_and_stack_maps() {
    let mut s = space();
    let h = s.process_heap();
    s.map(HEAP_START, 9, Owner::Module(7), Permissions::READ, true)
        .unwrap();
    s.map(
        HEAP_START + 24,
        7,
        Owner::Stack(8),
        Permissions::READ_WRITE,
        true,
    )
    .unwrap();
    let p = allocation(&mut s, 8, 8);
    assert_eq!(p, HEAP_START + 16);
    let q = s.heap_realloc(h, 0, p, 16, YES).unwrap().unwrap();
    assert_eq!(q, HEAP_START + 32);
    assert_eq!(
        s.heap_free(h, 0, HEAP_START),
        Err(HeapError::InvalidPointer)
    );
    assert_eq!(s.read(HEAP_START, 9).unwrap(), &[0; 9]);
    s.map(
        HEAP_START + 80,
        8,
        PROCESS_HEAP_OWNER,
        Permissions::READ_WRITE,
        true,
    )
    .unwrap();
    assert_eq!(
        s.heap_free(h, 0, HEAP_START + 80),
        Err(HeapError::InvalidPointer)
    );
}
#[test]
fn heap_full_width_and_wraparound_accesses_reject() {
    let mut s = space();
    let p = allocation(&mut s, 8, 8);
    assert_eq!(s.write(p + 7, &[1, 2]), Err(Fault::Range));
    assert_eq!(s.read(u32::MAX, 2), Err(Fault::Range));
    assert_eq!(s.read(p.wrapping_sub(1), 2), Err(Fault::Range));
    assert_eq!(
        s.heap_alloc(s.process_heap(), 8, u32::MAX, YES),
        Err(HeapError::Memory(Fault::Budget))
    );
    assert_eq!(s.read(p, 8).unwrap(), &[0; 8]);
}
#[test]
fn heap_counter_exhaustion_does_not_destroy_old_storage() {
    let mut s = space();
    let h = s.process_heap();
    let p = allocation(&mut s, 8, 8);
    let cap = s.heap_capability(h, p).unwrap();
    let fact = s.prove_read(cap, PROCESS_HEAP_OWNER, p, 8).unwrap();
    s.generation = u64::MAX;
    assert_eq!(
        s.heap_realloc(h, 0, p, 8, YES),
        Err(HeapError::Memory(Fault::Budget))
    );
    assert_eq!(
        s.heap_alloc(h, 0, 8, YES),
        Err(HeapError::Memory(Fault::Budget))
    );
    assert_eq!(s.read_proven(fact, PROCESS_HEAP_OWNER).unwrap(), &[0; 8]);
}
