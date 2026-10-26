use super::*;
fn put(b: &mut [u8], at: usize, value: u32) {
    b[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn image() -> Vec<u8> {
    let mut b = tests::fixture(&[0xb8, 7, 0, 0, 0, 0x05, 5, 0, 0, 0, 0xc3]);
    b.resize(0x600, 0);
    b[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
    for (at, v) in [
        (0x9c, 0x200),
        (0xa0, 0x200),
        (0xac, 0x1000),
        (0xb0, 0x2000),
        (0xd0, 0x3000),
        (0x1a8, 16),
        (0x1ac, 0x2000),
        (0x1b0, 0x200),
        (0x1b4, 0x400),
        (0x1c4, 0x40000040),
    ] {
        put(&mut b, at, v);
    }
    b[0x400..0x410].fill(0xff); // Deliberately unsupported opcodes, never decoded.
    b
}
#[test]
fn literal_two_section_ranges_and_data_independence() {
    let mut b = image();
    let p = Pe::parse(&b).unwrap();
    assert_eq!(p.sections.len(), 2);
    assert_eq!(p.entry_bytes().unwrap(), &b[0x200..0x300]);
    let source = control::translate(p.entry_bytes().unwrap()).unwrap();
    assert_eq!(
        control::exit_for_test(p.entry_bytes().unwrap()).unwrap(),
        12
    );
    b[0x400..0x600].fill(0);
    assert_eq!(
        control::translate(Pe::parse(&b).unwrap().entry_bytes().unwrap()).unwrap(),
        source
    );
    for (rva, start, len) in [
        (0x1000, 0x200, 0x100),
        (0x1005, 0x205, 0xfb),
        (0x10ff, 0x2ff, 1),
    ] {
        put(&mut b, 0xa8, rva);
        assert_eq!(
            Pe::parse(&b).unwrap().entry_bytes().unwrap(),
            &b[start..start + len]
        );
    }
    for rva in [
        0, 0x200, 0xfff, 0x1100, 0x1200, 0x1fff, 0x2000, 0x200f, 0x2010, 0x3000,
    ] {
        put(&mut b, 0xa8, rva);
        assert!(Pe::parse(&b).unwrap().entry_bytes().is_err());
    }
}
#[test]
fn malformed_mapping_table_is_rejected() {
    for (at, value) in [
        (0x1ac, 0x1000),
        (0x1ac, 0x3000),
        (0x1ac, 0x2001),
        (0x1ac, 0xfffff000),
        (0x1b4, 0x200),
        (0x1b4, 0),
        (0x1b4, 0x401),
        (0x1b4, 0xfffffe00),
        (0x1b0, 0),
        (0x1b0, 0x201),
        (0x1b0, 0x400),
        (0x1b0, 0xfffffe00),
        (0x1a8, 0),
        (0x1a8, 0x201),
        (0x1a8, u32::MAX),
        (0x1c4, 0x60000020),
        (0x1c4, 0xc0000040),
        (0x1c4, 0x40000080),
        (0x19c, 0x40000040),
        (0x19c, 0xe0000020),
        (0x1b8, 1),
        (0x1bc, 1),
        (0x1c0, 1),
        (0x190, 1),
        (0x194, 1),
        (0x198, 1),
        (0xd0, 0x2000),
        (0xd0, 0x4000),
        (0xd4, 0x400),
        (0x9c, 0),
        (0xa0, 0),
        (0xa4, 1),
        (0xac, 0x2000),
        (0xb0, 0x1000),
        (0x180, 0x1001),
        (0x188, 0x1200),
    ] {
        let mut b = image();
        put(&mut b, at, value);
        assert!(Pe::parse(&b).is_err(), "accepted {at:x}={value:x}");
    }
    let b = image();
    for end in 0..b.len() {
        assert!(Pe::parse(&b[..end]).is_err(), "prefix {end:x}");
    }
    for count in [0u16, 3, u16::MAX] {
        let mut b = image();
        b[0x86..0x88].copy_from_slice(&count.to_le_bytes());
        assert!(Pe::parse(&b).is_err());
    }
}
#[test]
fn code_bounds_do_not_authorize_padding_data_or_memory() {
    let mut b = image();
    put(&mut b, 0x180, 5); // MOV ends exactly where executable bytes stop.
    assert!(control::translate(Pe::parse(&b).unwrap().entry_bytes().unwrap()).is_err());
    let mut b = image();
    put(&mut b, 0x180, 0x300);
    put(&mut b, 0xa8, 0x1200); // Zero-filled code tail.
    assert!(Pe::parse(&b).unwrap().entry_bytes().is_err());
    let mut b = image();
    b[0x200..0x206].copy_from_slice(&[0xa1, 0, 0x20, 0x40, 0, 0xc3]);
    assert!(control::translate(Pe::parse(&b).unwrap().entry_bytes().unwrap()).is_err());
    let mut b = image();
    b[0x200..0x206].copy_from_slice(&[0xe8, 0xfb, 0x0f, 0, 0, 0xc3]); // Target data RVA2000.
    assert!(control::translate(Pe::parse(&b).unwrap().entry_bytes().unwrap()).is_err());
    for i in 0..16 {
        let mut b = image();
        put(&mut b, 0xf8 + i * 8, 0x2000);
        assert!(Pe::parse(&b).is_err());
    }
}

#[test]
fn aligned_virtual_extent_and_raw_gap_boundaries() {
    let mut b = image();
    put(&mut b, 0x180, 0x1000);
    assert!(Pe::parse(&b).is_ok()); // Exact page end remains adjacent to data2000.
    put(&mut b, 0x180, 0x1001);
    assert!(Pe::parse(&b).is_err()); // Virtual tail overlaps data despite tiny raw code.
    put(&mut b, 0x1ac, 0x3000);
    put(&mut b, 0xb0, 0x3000);
    put(&mut b, 0xd0, 0x4000);
    assert_eq!(Pe::parse(&b).unwrap().entry_bytes().unwrap().len(), 0x200);
    put(&mut b, 0xa8, 0x1200);
    assert!(Pe::parse(&b).unwrap().entry_bytes().is_err());
    let mut b = image();
    b.resize(0x800, 0);
    b.copy_within(0x400..0x600, 0x600);
    put(&mut b, 0x1b4, 0x600); // Permitted aligned raw gap, not an RVA gap.
    put(&mut b, 0x1a8, 0x200);
    let p = Pe::parse(&b).unwrap();
    assert_eq!(
        control::exit_for_test(p.entry_bytes().unwrap()).unwrap(),
        12
    );
    put(&mut b, 0x1a8, 0x201);
    assert!(Pe::parse(&b).is_err());
}
