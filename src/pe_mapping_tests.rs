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

fn load_code(address: u32) -> Vec<u8> {
    let mut code = vec![0xa1];
    code.extend(address.to_le_bytes());
    code
}
fn with_code(code: &[u8]) -> Vec<u8> {
    let mut b = image();
    b[0x200..0x300].fill(0);
    b[0x200..0x200 + code.len()].copy_from_slice(code);
    b
}
#[test]
fn immutable_reads_use_full_width_little_endian_and_preferred_base() {
    let mut b = image();
    b[0x400..0x410].copy_from_slice(&[
        7, 0, 0, 0, 0x78, 0x56, 0x34, 0x12, 255, 255, 255, 255, 12, 0, 0, 0,
    ]);
    for (address, expected) in [
        (0x402000, 7),
        (0x402001, 0x78000000),
        (0x402004, 0x12345678),
        (0x402008, u32::MAX),
        (0x40200c, 12),
    ] {
        assert_eq!(
            Pe::parse(&b).unwrap().read_immutable_u32(address).unwrap(),
            expected
        );
    }
    put(&mut b, 0xb4, 0x500000);
    assert_eq!(
        Pe::parse(&b).unwrap().read_immutable_u32(0x502000).unwrap(),
        7
    );
    assert!(Pe::parse(&b).unwrap().read_immutable_u32(0x402000).is_err());
    for address in [
        0, 0x4fffff, 0x500000, 0x501000, 0x501fff, 0x50200d, 0x502010, 0x5021fc, 0x503000,
        0xfffffffe,
    ] {
        assert!(
            Pe::parse(&b).unwrap().read_immutable_u32(address).is_err(),
            "{address:x}"
        );
    }
    b[0x410..0x600].fill(7);
    assert!(Pe::parse(&b).unwrap().read_immutable_u32(0x502010).is_err());
    let one = tests::fixture(&[0xc3]);
    assert!(Pe::parse(&one)
        .unwrap()
        .read_immutable_u32(0x402000)
        .is_err());
}
#[test]
fn production_translation_resolves_data_preserves_flags_and_rejects_untaken_reads() {
    let mut code = load_code(0x402000);
    code.extend([0x05, 5, 0, 0, 0, 0xc3]);
    let mut b = with_code(&code);
    put(&mut b, 0x400, 7);
    let expected = control::translate(&[0xb8, 7, 0, 0, 0, 0x05, 5, 0, 0, 0, 0xc3]).unwrap();
    assert_eq!(Pe::parse(&b).unwrap().translate().unwrap(), expected);
    put(&mut b, 0x400, 9);
    assert_eq!(
        Pe::parse(&b).unwrap().translate().unwrap(),
        control::translate(&[0xb8, 9, 0, 0, 0, 0x05, 5, 0, 0, 0, 0xc3]).unwrap()
    );
    assert!(control::translate(&code).unwrap_err().contains("context"));
    let mut untaken = vec![0x31, 0xc0, 0x74, 5];
    untaken.extend(load_code(0x401000));
    untaken.push(0xc3);
    assert!(Pe::parse(&with_code(&untaken))
        .unwrap()
        .translate()
        .is_err());
    for prefix in [
        vec![],
        vec![0x31, 0xc0],
        vec![0xb8, 255, 255, 255, 255, 0x05, 1, 0, 0, 0],
    ] {
        let mut code = prefix.clone();
        code.extend(load_code(0x402000));
        code.extend([0x74, 0, 0xc3]);
        let mut b = with_code(&code);
        put(&mut b, 0x400, 7);
        let result = Pe::parse(&b).unwrap().translate();
        if prefix.is_empty() {
            assert!(result.unwrap_err().contains("unknown entry flags"));
        } else {
            let mut expected = prefix;
            expected.extend([0xb8, 7, 0, 0, 0, 0x74, 0, 0xc3]);
            assert_eq!(result.unwrap(), control::translate(&expected).unwrap());
        }
    }
    // Shared helper and a branch join resolve the same data with preserved context.
    let mut code = vec![
        0x31, 0xc0, 0xe8, 8, 0, 0, 0, 0xe8, 3, 0, 0, 0, 0x74, 0, 0xc3,
    ];
    code.extend(load_code(0x402000));
    code.push(0xc3);
    let mut b = with_code(&code);
    put(&mut b, 0x400, 7);
    assert!(Pe::parse(&b).unwrap().translate().is_ok());
}
#[test]
fn exact_absolute_load_policy_and_production_negative_addresses() {
    let code = load_code(0x402000);
    assert_eq!(
        control::decode_instruction(&code, 0).unwrap().op,
        control::Op::LoadAbsolute(0x402000)
    );
    for end in 0..5 {
        assert!(control::decode_instruction(&code[..end], 0).is_err());
    }
    for prefix in [
        0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65, 0x66, 0x67,
    ] {
        let mut bytes = vec![prefix];
        bytes.extend(&code);
        bytes.push(0xc3);
        assert!(Pe::parse(&with_code(&bytes)).unwrap().translate().is_err());
    }
    for bytes in [
        &[0xa0, 0, 0x20, 0x40, 0][..],
        &[0xa3, 0, 0x20, 0x40, 0],
        &[0x8b, 0x05, 0, 0x20, 0x40, 0],
        &[0x8b, 0x0d, 0, 0x20, 0x40, 0],
    ] {
        assert!(Pe::parse(&with_code(bytes)).unwrap().translate().is_err());
    }
    for address in [
        0x3fffff,
        0x400000,
        0x401000,
        0x401fff,
        0x40200d,
        0x402010,
        0x4021ff,
        u32::MAX,
    ] {
        let mut bytes = load_code(address);
        bytes.push(0xc3);
        assert!(Pe::parse(&with_code(&bytes)).unwrap().translate().is_err());
    }
}

#[test]
fn immutable_context_stays_bound_to_each_image_and_file_mapping() {
    let mut code = load_code(0x402000);
    code.extend([0x05, 5, 0, 0, 0, 0xc3]);
    let mut first = with_code(&code);
    put(&mut first, 0x400, 7);
    let mut second = with_code(&code);
    second.resize(0x800, 0);
    put(&mut second, 0x1b4, 0x600);
    put(&mut second, 0x600, 9);
    put(&mut second, 0x400, 99); // Stale original file offset must not be consulted.
    let a = Pe::parse(&first).unwrap();
    let b = Pe::parse(&second).unwrap();
    let expected_a = control::translate(&[0xb8, 7, 0, 0, 0, 0x05, 5, 0, 0, 0, 0xc3]).unwrap();
    let expected_b = control::translate(&[0xb8, 9, 0, 0, 0, 0x05, 5, 0, 0, 0, 0xc3]).unwrap();
    for _ in 0..3 {
        assert_eq!(a.translate().unwrap(), expected_a);
        assert_eq!(b.translate().unwrap(), expected_b);
    }
    assert_ne!(expected_a, expected_b);
}
