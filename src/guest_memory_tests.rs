use super::*;
const HEAP: Owner = Owner::Heap(9);
fn space() -> Space {
    Space::new(128, 8).unwrap()
}

#[test]
fn aliases_defined_bytes_and_unknown_tail() {
    let mut s = space();
    let c = s
        .map(0x1000, 8, HEAP, Permissions::READ_WRITE, false)
        .unwrap();
    assert_eq!(s.read(0x1000, 1), Err(Fault::Uninitialized));
    s.write(0x1001, &[0x12, 0x34, 0x56, 0x78]).unwrap();
    assert_eq!(s.read(0x1002, 2).unwrap(), &[0x34, 0x56]);
    s.write(0x1003, &[0xab]).unwrap();
    assert_eq!(s.read(0x1001, 4).unwrap(), &[0x12, 0x34, 0xab, 0x78]);
    assert_eq!(s.prove_read(c, HEAP, 0x1000, 5), Err(Fault::Uninitialized));
}
#[test]
fn full_ranges_adjacent_regions_and_wrapped_effective_addresses() {
    let mut s = space();
    s.map(0xfffffffc, 4, HEAP, Permissions::READ_WRITE, true)
        .unwrap();
    s.map(0x1000, 4, HEAP, Permissions::READ_WRITE, true)
        .unwrap();
    s.map(0x1004, 4, HEAP, Permissions::READ_WRITE, true)
        .unwrap();
    assert_eq!(s.read(0xfffffffc, 4).unwrap(), &[0; 4]);
    for (p, n) in [
        (0xfffffffd, 4),
        (0xffffffff, 2),
        (0x1002, 4),
        (0, 1),
        (0x1000, 0),
        (0x1008, 1),
    ] {
        assert_eq!(s.read(p, n), Err(Fault::Range), "{p:x}/{n}");
    }
    let ea = 0xfffffff0u32.wrapping_add(0x1010);
    assert_eq!(ea, 0x1000);
    s.write(ea, &[1, 2, 3, 4]).unwrap();
    assert_eq!(s.read(0x1000, 4).unwrap(), &[1, 2, 3, 4]);
    assert_eq!(
        s.map(0x1003, 2, HEAP, Permissions::READ, true),
        Err(Fault::Overlap)
    );
    assert_eq!(
        s.map(0xffffffff, 2, HEAP, Permissions::READ, true),
        Err(Fault::Range)
    );
}
#[test]
fn image_zero_fill_permissions_and_no_writable_executable_mapping() {
    let mut s = space();
    let c = s
        .map_image(0x400000, 8, 2, Permissions::READ_EXECUTE, &[0xc3, 0x90])
        .unwrap();
    assert_eq!(
        s.read(0x400000, 8).unwrap(),
        &[0xc3, 0x90, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(s.write(0x400000, &[1]), Err(Fault::Permission));
    assert_eq!(s.destination(0x400000, 1), Err(Fault::Permission));
    assert_eq!(s.forget(0x400000, 1), Err(Fault::Permission));
    assert_eq!(s.define(0x400000, 1), Err(Fault::Permission));
    assert_eq!(s.validate(c, Owner::Module(3)), Err(Fault::Identity));
    assert_eq!(
        s.map(
            0x1000,
            8,
            HEAP,
            Permissions {
                read: true,
                write: true,
                execute: true
            },
            true
        ),
        Err(Fault::Permission)
    );
    let p = Permissions {
        read: false,
        write: true,
        execute: false,
    };
    s.map(0x2000, 4, HEAP, p, true).unwrap();
    assert_eq!(s.read(0x2000, 1), Err(Fault::Permission));
}
#[test]
fn process_collision_owner_and_reuse_preserve_numeric_aliasing() {
    let mut a = space();
    let mut b = space();
    let ca = a
        .map(0x1000, 4, HEAP, Permissions::READ_WRITE, true)
        .unwrap();
    let cb = b
        .map(0x1000, 4, HEAP, Permissions::READ_WRITE, true)
        .unwrap();
    assert_eq!(
        (ca.base, ca.generation, ca.owner),
        (cb.base, cb.generation, cb.owner)
    );
    assert_ne!(ca.process, cb.process);
    assert_eq!(b.validate(ca, HEAP), Err(Fault::Identity));
    assert_eq!(b.release(ca, HEAP), Err(Fault::Identity));
    assert_eq!(a.validate(ca, Owner::Heap(10)), Err(Fault::Identity));
    a.release(ca, HEAP).unwrap();
    assert_eq!(a.read(0x1000, 1), Err(Fault::Range));
    let new = a
        .map(0x1000, 4, HEAP, Permissions::READ_WRITE, true)
        .unwrap();
    a.write(0x1000, &[7, 8, 9, 10]).unwrap();
    assert_eq!(a.validate(ca, HEAP), Err(Fault::Stale));
    assert_eq!(a.read(0x1000, 4).unwrap(), &[7, 8, 9, 10]);
    a.validate(new, HEAP).unwrap();
}
#[test]
fn freshness_is_not_physical_definedness_and_ranges_cannot_escape_owner() {
    let mut s = space();
    let c = s
        .map(0x1000, 8, HEAP, Permissions::READ_WRITE, true)
        .unwrap();
    s.map(0x2000, 8, Owner::Heap(10), Permissions::READ_WRITE, true)
        .unwrap();
    s.write(0x1000, &[10, 20, 30, 40, 50, 60, 70, 80]).unwrap();
    let fact = s.prove_read(c, HEAP, 0x1000, 8).unwrap();
    assert_eq!(s.prove_read(c, HEAP, 0x2000, 1), Err(Fault::Identity));
    s.destination(0x1000, 8).unwrap()[..2].copy_from_slice(&[90, 91]);
    s.define(0x1000, 2).unwrap();
    assert_eq!(s.read_proven(fact, HEAP), Err(Fault::Stale));
    assert_eq!(
        s.read(0x1000, 8).unwrap(),
        &[90, 91, 30, 40, 50, 60, 70, 80]
    );
    let fresh = s.prove_read(c, HEAP, 0x1000, 2).unwrap();
    assert_eq!(s.read_proven(fresh, HEAP).unwrap(), &[90, 91]);
    s.forget(0x1002, 6).unwrap();
    assert_eq!(s.read(0x1002, 1), Err(Fault::Uninitialized));
}
#[test]
fn moving_storage_preserves_prefix_definedness_and_failure_is_atomic() {
    let mut s = space();
    let c = s
        .map(0x1000, 4, HEAP, Permissions::READ_WRITE, false)
        .unwrap();
    s.write(0x1000, &[0xde, 0xad]).unwrap();
    let fact = s.prove_read(c, HEAP, 0x1000, 2).unwrap();
    assert_eq!(
        s.move_resize(c, HEAP, 0x2000, 128, false),
        Err(Fault::Budget)
    );
    assert_eq!(
        s.move_resize(c, HEAP, 0x1002, 8, false),
        Err(Fault::Overlap)
    );
    assert_eq!(s.read_proven(fact, HEAP).unwrap(), &[0xde, 0xad]);
    let d = s.move_resize(c, HEAP, 0x2000, 8, true).unwrap();
    assert_eq!(s.read(0x1000, 1), Err(Fault::Range));
    assert_eq!(s.validate(c, HEAP), Err(Fault::Stale));
    assert_eq!(s.read(0x2000, 2).unwrap(), &[0xde, 0xad]);
    assert_eq!(s.read(0x2002, 2), Err(Fault::Uninitialized));
    assert_eq!(s.read(0x2004, 4).unwrap(), &[0; 4]);
    let e = s.move_resize(d, HEAP, 0x3000, 1, false).unwrap();
    assert_eq!(s.read(0x3000, 1).unwrap(), &[0xde]);
    s.validate(e, HEAP).unwrap();
}
#[test]
fn finite_budgets_and_failed_mutation_preserve_facts() {
    let mut s = Space::new(8, 1).unwrap();
    let c = s
        .map(0x1000, 8, HEAP, Permissions::READ_WRITE, true)
        .unwrap();
    let fact = s.prove_read(c, HEAP, 0x1000, 8).unwrap();
    assert_eq!(
        s.map(0x2000, 1, HEAP, Permissions::READ, true),
        Err(Fault::Budget)
    );
    assert_eq!(s.write(0x1007, &[1, 2]), Err(Fault::Range));
    assert_eq!(s.read_proven(fact, HEAP).unwrap(), &[0; 8]);
    s.regions[0].epoch = u64::MAX - 1;
    assert_eq!(s.write(0x1000, &[1]), Err(Fault::Budget));
    assert_eq!(s.read(0x1000, 1).unwrap(), &[0]);
    s.release(c, HEAP).unwrap();
    s.map(0x2000, 8, HEAP, Permissions::READ, true).unwrap();
    assert!(matches!(Space::new(MAX_BYTES + 1, 1), Err(Fault::Budget)));
    assert!(matches!(Space::new(1, MAX_REGIONS + 1), Err(Fault::Budget)));
}
