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

fn protection_space() -> (Space, Capability, Capability) {
    let mut s = Space::new(32768, 8).unwrap();
    let data = s
        .map_image(0x10000, 3 * PAGE_SIZE, 7, Permissions::READ_WRITE, &[9; 16])
        .unwrap();
    let out = s
        .map(
            0x20000,
            PAGE_SIZE,
            Owner::Stack(8),
            Permissions::READ_WRITE,
            false,
        )
        .unwrap();
    s.write(0x20000, &0xdeadbeefu32.to_le_bytes()).unwrap();
    (s, data, out)
}
#[test]
fn page_protection_rounding_first_old_value_and_aliases() {
    let (mut s, data, out) = protection_space();
    let fact = s.prove_read(data, Owner::Module(7), 0x10000, 4).unwrap();
    s.protect_data_with_old(
        (data, Owner::Module(7), 0x10fff, 2),
        2,
        (out, Owner::Stack(8), 0x20000),
    )
    .unwrap();
    assert_eq!(s.read(0x20000, 4).unwrap(), &4u32.to_le_bytes());
    for at in [0x10000, 0x10fff, 0x11000, 0x11fff] {
        assert_eq!(s.write(at, &[1]), Err(Fault::Permission));
    }
    s.write(0x12000, &[5]).unwrap();
    assert_eq!(s.read_proven(fact, Owner::Module(7)), Err(Fault::Stale));
    s.validate(data, Owner::Module(7)).unwrap();
    assert_eq!(s.read(0x10000, 4).unwrap(), &[9; 4]);
    // The pages now differ. Old protection is from the FIRST page only.
    s.protect_data_with_old(
        (data, Owner::Module(7), 0x11fff, 2),
        4,
        (out, Owner::Stack(8), 0x20000),
    )
    .unwrap();
    assert_eq!(s.read(0x20000, 4).unwrap(), &2u32.to_le_bytes());
    s.write(0x11000, &[7]).unwrap();
    assert_eq!(s.write(0x10000, &[1]), Err(Fault::Permission));
}
#[test]
fn page_protection_failures_are_atomic() {
    for mode in 0..10 {
        let (mut s, data, out) = protection_space();
        let (mut address, mut size, mut flags, mut output) = (0x10001, 1, 2, 0x20000);
        match mode {
            0 => size = 0,
            1 => {
                address = 0x12fff;
                size = 2;
            }
            2 => flags = 0x40,
            3 => flags = 0x102,
            4 => output = 0x20ffe,
            5 => output = 0x10fff,
            6 => {
                address = u32::MAX;
                size = 2;
            }
            7 => output = 0,
            8 => s.release(out, Owner::Stack(8)).unwrap(),
            9 => {
                s.regions[1].epoch = u64::MAX;
            }
            _ => unreachable!(),
        }
        let data_epoch = s.regions[0].epoch;
        let got = s.protect_data_with_old(
            (data, Owner::Module(7), address, size),
            flags,
            (out, Owner::Stack(8), output),
        );
        assert!(got.is_err(), "mode {mode} unexpectedly protected");
        assert_eq!(s.regions[0].epoch, data_epoch);
        s.validate_writable(data, Owner::Module(7), 0x10000, 3 * PAGE_SIZE)
            .unwrap();
        if mode != 8 {
            assert_eq!(s.read(0x20000, 4).unwrap(), &0xdeadbeefu32.to_le_bytes());
        }
    }
}
#[test]
fn page_protection_stale_cross_process_and_executable_reject() {
    let (mut s, data, out) = protection_space();
    let (other, foreign, _) = protection_space();
    assert_ne!(s.identity, other.identity);
    assert_eq!(
        s.protect_data_with_old(
            (foreign, Owner::Module(7), 0x10000, 1),
            2,
            (out, Owner::Stack(8), 0x20000)
        ),
        Err(Fault::Identity)
    );
    s.release(data, Owner::Module(7)).unwrap();
    let code = s
        .map_image(
            0x10000,
            3 * PAGE_SIZE,
            7,
            Permissions::READ_EXECUTE,
            &[0xc3],
        )
        .unwrap();
    assert_eq!(
        s.protect_data_with_old(
            (data, Owner::Module(7), 0x10000, 1),
            2,
            (out, Owner::Stack(8), 0x20000)
        ),
        Err(Fault::Stale)
    );
    assert_eq!(
        s.protect_data_with_old(
            (code, Owner::Module(7), 0x10000, 1),
            4,
            (out, Owner::Stack(8), 0x20000)
        ),
        Err(Fault::Permission)
    );
    s.validate_executable(code, Owner::Module(7), 0x10000, 1)
        .unwrap();
    assert_eq!(s.read(0x20000, 4).unwrap(), &0xdeadbeefu32.to_le_bytes());
}
#[test]
fn protection_does_not_define_unknown_bytes_or_grow_mapping() {
    let (mut s, data, out) = protection_space();
    s.forget(0x10008, 1).unwrap();
    s.protect_data_with_old(
        (data, Owner::Module(7), 0x10000, 1),
        1,
        (out, Owner::Stack(8), 0x20000),
    )
    .unwrap();
    assert_eq!(s.read(0x10000, 1), Err(Fault::Permission));
    assert_eq!(
        s.validate_readable(data, Owner::Module(7), 0x10000, 1),
        Err(Fault::Permission)
    );
    s.protect_data_with_old(
        (data, Owner::Module(7), 0x10000, 1),
        2,
        (out, Owner::Stack(8), 0x20000),
    )
    .unwrap();
    assert_eq!(s.read(0x10008, 1), Err(Fault::Uninitialized));
    let short = s
        .map_image(0x30000, 128, 7, Permissions::READ_WRITE, &[5])
        .unwrap();
    s.protect_data_with_old(
        (short, Owner::Module(7), 0x30000, 128),
        2,
        (out, Owner::Stack(8), 0x20000),
    )
    .unwrap();
    assert_eq!(s.read(0x30080, 1), Err(Fault::Range));
    assert_eq!(
        s.map(0x30080, 128, Owner::Stack(9), Permissions::READ_WRITE, true),
        Err(Fault::Overlap)
    );
    // Existing partial neighboring mappings also block protection atomically.
    let another = s
        .map_image(0x40000, 128, 7, Permissions::READ_WRITE, &[5])
        .unwrap();
    s.map(0x40080, 128, Owner::Stack(9), Permissions::READ_WRITE, true)
        .unwrap();
    assert_eq!(
        s.protect_data_with_old(
            (another, Owner::Module(7), 0x40000, 1),
            2,
            (out, Owner::Stack(8), 0x20000)
        ),
        Err(Fault::Overlap)
    );
    s.validate_writable(another, Owner::Module(7), 0x40000, 1)
        .unwrap();
}
#[test]
fn same_mapping_output_other_page_preserves_identity_and_first_value() {
    let (mut s, data, _) = protection_space();
    let fact = s.prove_read(data, Owner::Module(7), 0x12000, 4).unwrap();
    s.protect_data_with_old(
        (data, Owner::Module(7), 0x10000, 1),
        2,
        (data, Owner::Module(7), 0x12000),
    )
    .unwrap();
    assert_eq!(s.read(0x12000, 4).unwrap(), &4u32.to_le_bytes());
    assert_eq!(s.read_proven(fact, Owner::Module(7)), Err(Fault::Stale));
    s.validate_writable(data, Owner::Module(7), 0x12000, 4)
        .unwrap();
}

#[test]
fn mixed_permissions_invalidate_immutable_snapshots() {
    let (mut s, data, out) = protection_space();
    s.protect_data_with_old(
        (data, Owner::Module(7), 0x10000, 3 * PAGE_SIZE),
        2,
        (out, Owner::Stack(8), 0x20000),
    )
    .unwrap();
    s.validate_immutable(data, Owner::Module(7), 0x10000, 3 * PAGE_SIZE)
        .unwrap();
    s.protect_data_with_old(
        (data, Owner::Module(7), 0x11000, 1),
        4,
        (out, Owner::Stack(8), 0x20000),
    )
    .unwrap();
    assert_eq!(
        s.validate_writable(data, Owner::Module(7), 0x10000, 3 * PAGE_SIZE),
        Err(Fault::Permission)
    );
    assert_eq!(
        s.validate_immutable(data, Owner::Module(7), 0x10000, 3 * PAGE_SIZE),
        Err(Fault::Permission)
    );
    s.validate_immutable(data, Owner::Module(7), 0x10000, PAGE_SIZE)
        .unwrap();
}
#[test]
fn protection_epoch_and_output_permission_preflight() {
    for mode in 0..3 {
        let (mut s, data, out) = protection_space();
        if mode == 0 {
            s.regions[0].epoch = u64::MAX;
        }
        if mode == 1 {
            s.regions[1].pages.fill(Permissions::READ);
        }
        if mode == 2 {
            s.regions[0].epoch = u64::MAX - 1;
        }
        let output = if mode == 2 {
            (data, Owner::Module(7), 0x12000)
        } else {
            (out, Owner::Stack(8), 0x20000)
        };
        assert_eq!(
            s.protect_data_with_old((data, Owner::Module(7), 0x10000, 1), 2, output),
            Err(if mode == 1 {
                Fault::Permission
            } else {
                Fault::Budget
            })
        );
        s.validate_writable(data, Owner::Module(7), 0x10000, 1)
            .unwrap();
        assert_eq!(s.read(0x20000, 4).unwrap(), &0xdeadbeefu32.to_le_bytes());
    }
}
