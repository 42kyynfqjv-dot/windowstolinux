use super::*;
fn put(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn short(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
fn specimen() -> Vec<u8> {
    let mut b = vec![0; 2048];
    b[..2].copy_from_slice(b"MZ");
    put(&mut b, 60, 128);
    b[128..132].copy_from_slice(b"PE\0\0");
    for (at, n) in [
        (132, 0x14c),
        (134, 2),
        (148, 224),
        (150, 0x102),
        (152, 0x10b),
        (220, 3),
        (222, 0x8540),
    ] {
        short(&mut b, at, n);
    }
    for (at, n) in [
        (168, 0x1000),
        (180, 0x400000),
        (184, 4096),
        (188, 512),
        (208, 0x3000),
        (212, 1024),
        (224, 0x100000),
        (228, 4096),
        (232, 0x100000),
        (236, 4096),
        (244, 16),
    ] {
        put(&mut b, at, n);
    }
    for (at, va, raw, flags) in [
        (376, 0x1000, 1024, 0x60000020),
        (416, 0x2000, 1536, 0x40000040),
    ] {
        for (off, n) in [(8, 32), (12, va), (16, 512), (20, raw), (36, flags)] {
            put(&mut b, at + off, n);
        }
    }
    b[1024..1030].copy_from_slice(&[0xb8, 12, 0, 0, 0, 0xc3]);
    b
}
#[test]
fn literal_layout_not_execution_authority() {
    let b = specimen();
    let p = Envelope::parse(b.clone()).unwrap();
    assert_eq!(p.file_location(0x201f, 1).unwrap().1, 1567);
    assert!(p.file_location(0x201f, 2).is_err());
    assert!(p.closed);
    assert!(p.pointers.is_empty());
    assert_eq!(p.blockers, ["instruction-ABI-and-provenance-proof-not-run"]);
    assert!(p.report().contains("\"emission_allowed\":false"));
    assert_eq!(inspect(b.clone()).unwrap(), inspect(b).unwrap());
}
#[test]
fn malformed_ranges_permissions_architecture_and_startup() {
    for (at, n) in [
        (60, 0xfffffff8),
        (208, 0x200000),
        (212, 256),
        (388, 0x2000),
        (436, 1024),
        (432, 513),
        (424, 0x201),
        (412, 0xe0000020),
        (168, 0x1020),
        (180, 0xffff0001),
        (244, 17),
        (248, 0x2000),
    ] {
        let mut b = specimen();
        put(&mut b, at, n);
        assert!(inspect(b).is_err(), "{at}");
    }
    for (at, n) in [
        (132, 0x8664),
        (152, 0x20b),
        (150, 0x2102),
        (222, 0xc540),
        (148, 95),
    ] {
        let mut b = specimen();
        short(&mut b, at, n);
        assert!(inspect(b).is_err());
    }
    for index in [1, 9, 10, 12, 13, 14] {
        let mut b = specimen();
        put(&mut b, 248 + 8 * index, 0x2000);
        put(&mut b, 252 + 8 * index, 8);
        let p = Envelope::parse(b).unwrap();
        assert!(!p.closed);
        assert!(p.report().contains("\"emission_allowed\":false"));
    }
}
#[test]
fn whole_file_truncations_and_nonwrapping_endpoint() {
    let b = specimen();
    for n in 0..b.len() {
        assert!(inspect(b[..n].to_vec()).is_err(), "length {n}");
    }
    assert_eq!(end(0xfffffff0, 15).unwrap(), 0xffffffff);
    assert!(end(0xfffffff0, 16).is_err());
}
#[test]
fn zero_fill_never_produces_a_file_coordinate() {
    let mut b = specimen();
    put(&mut b, 424, 516);
    put(&mut b, 452, 0xc0000040);
    let p = Envelope::parse(b).unwrap();
    assert_eq!(p.locate(0x2200, 4, false).unwrap().1, None);
    assert!(p.locate(0x2200, 4, true).is_err());
    assert!(p.locate(0x2203, 2, false).is_err());
    assert!(p
        .blockers
        .contains(&"writable-memory-unimplemented".to_string()));
}
#[test]
fn metadata_alias_and_snapshot_isolation() {
    let mut b = specimen();
    for i in [9, 10] {
        put(&mut b, 248 + 8 * i, 0x2000);
        put(&mut b, 252 + 8 * i, 8);
    }
    assert!(inspect(b).unwrap_err().contains("alias"));
    let b = specimen();
    let p = Envelope::parse(b.clone()).unwrap();
    let mut other = b;
    put(&mut other, 168, 0x1001);
    assert_ne!(p.report(), inspect(other).unwrap());
    assert_eq!(p.entry, 0x1000);
}
#[test]
fn relocation_candidates_are_unbound_and_reject_malformed_records() {
    let mut b = specimen();
    b.resize(3072, 0);
    short(&mut b, 134, 4);
    put(&mut b, 208, 0x5000);
    for (at, va, raw, flags, vs) in [
        (456, 0x3000, 2048, 0xc0000040, 4),
        (496, 0x4000, 2560, 0x42000040, 12),
    ] {
        for (off, n) in [(8, vs), (12, va), (16, 512), (20, raw), (36, flags)] {
            put(&mut b, at + off, n);
        }
    }
    put(&mut b, 288, 0x4000);
    put(&mut b, 292, 12);
    put(&mut b, 2560, 0x1000);
    put(&mut b, 2564, 12);
    short(&mut b, 2568, 0x3001);
    put(&mut b, 1025, 0x403000);
    let p = Envelope::parse(b.clone()).unwrap();
    assert_eq!(p.pointers.len(), 1);
    assert_eq!(p.pointers[0].rva, 0x3000);
    assert!(p.report().contains("\"bound\":false"));
    for (at, n) in [
        (2564, 8),
        (2564, 16),
        (2560, 1),
        (1025, 0x403004),
        (1025, 0x401000),
        (1025, 0x3fffff),
    ] {
        let mut bad = b.clone();
        put(&mut bad, at, n);
        assert!(inspect(bad).is_err());
    }
    for (at, n) in [
        (2568, 0xa001),
        (2570, 0x3001),
        (2570, 0x3003),
        (2568, 0x301e),
        (150, 0x103),
    ] {
        let mut bad = b.clone();
        short(&mut bad, at, n);
        assert!(inspect(bad).is_err());
    }
}
