use super::*;

#[test]
fn terminal_and_rejected_transitions_are_atomic() {
    let mut s = Stack::new();
    for eax in [None, Some(256), Some(u32::MAX)] {
        let before = s.clone();
        assert!(s.ret(eax).is_err());
        assert_eq!(s, before);
    }
    s.words.push(Word::Data {
        owner: 99,
        value: 7,
    });
    let before = s.clone();
    assert!(s.cleanup().is_err());
    assert!(s.ret(Some(0)).is_err());
    assert_eq!(s, before);
    s.call(10).unwrap();
    let before = s.clone();
    assert!(s.argument().is_err());
    assert!(s.cleanup().is_err());
    assert_eq!(s, before);
    if let Some(w) = s.words.last_mut() {
        *w = Word::Return {
            frame: 99,
            parent: 0,
            next: 10,
        };
    }
    let before = s.clone();
    assert!(s.ret(Some(0)).is_err());
    assert_eq!(s, before);
    let mut s = Stack::new();
    assert_eq!(s.ret(Some(12)), Ok(Return::Exit(12)));
    let terminal = s.clone();
    assert!(s.push(7).is_err());
    assert!(s.call(10).is_err());
    assert!(s.argument().is_err());
    assert!(s.cleanup().is_err());
    assert!(s.ret(Some(0)).is_err());
    assert_eq!(s, terminal);
}

#[test]
fn concrete_byte_layout_and_nested_frame_restoration() {
    // Independently specified little-endian x86 memory writes and ESP changes;
    // numeric return addresses exist only in this test, never in production state.
    for incoming in [0x1000u32, 0x7ffffffc, 0x80000000] {
        let mut memory = std::collections::BTreeMap::new();
        let mut esp = incoming;
        let mut s = Stack::new();
        for (data, return_eip, continuation) in
            [(0x12345678u32, 0x40100au32, 10), (11, 0x401020, 32)]
        {
            esp -= 4;
            for (i, byte) in data.to_le_bytes().into_iter().enumerate() {
                memory.insert(esp + i as u32, byte);
            }
            s.push(data).unwrap();
            esp -= 4;
            for (i, byte) in return_eip.to_le_bytes().into_iter().enumerate() {
                memory.insert(esp + i as u32, byte);
            }
            s.call(continuation).unwrap();
            let concrete =
                u32::from_le_bytes(std::array::from_fn(|i| memory[&(esp + 4 + i as u32)]));
            assert_eq!(concrete, data);
            assert_eq!(s.argument(), Ok(concrete));
            assert_eq!(esp, incoming - 4 * (s.words.len() as u32 - 1));
        }
        let saved_eip = u32::from_le_bytes(std::array::from_fn(|i| memory[&(esp + i as u32)]));
        assert_eq!(saved_eip, 0x401020);
        assert_eq!(s.ret(None), Ok(Return::Resume(32)));
        esp += 4;
        assert!(s.argument().is_err()); // Local data still displaces outer return.
        s.cleanup().unwrap();
        esp += 4;
        let outer = u32::from_le_bytes(std::array::from_fn(|i| memory[&(esp + 4 + i as u32)]));
        assert_eq!(s.argument(), Ok(outer));
        assert_eq!(outer, 0x12345678);
        let saved_eip = u32::from_le_bytes(std::array::from_fn(|i| memory[&(esp + i as u32)]));
        assert_eq!(saved_eip, 0x40100a);
        assert_eq!(s.ret(Some(u32::MAX)), Ok(Return::Resume(10)));
        esp += 4;
        s.cleanup().unwrap();
        esp += 4;
        assert_eq!(esp, incoming);
        assert_eq!(s.words, vec![Word::Entry]);
        assert!(s.argument().is_err()); // Old bytes remain in memory, inaccessible.
        assert_eq!(s.ret(Some(12)), Ok(Return::Exit(12)));
    }
}

#[test]
fn limits_include_return_words_and_rejections_do_not_mutate() {
    let mut s = Stack::new();
    for _ in 0..127 {
        s.push(0).unwrap();
    }
    s.call(10).unwrap();
    let before = s.clone();
    assert!(s.push(0).is_err());
    assert!(s.call(20).is_err());
    assert_eq!(s, before);
    assert_eq!(s.ret(None), Ok(Return::Resume(10)));
    s.push(1).unwrap();
    let before = s.clone();
    assert!(s.call(10).is_err());
    assert_eq!(s, before);
    let mut s = Stack::new();
    for i in 0..32 {
        s.call(i).unwrap();
    }
    let before = s.clone();
    assert!(s.call(33).is_err());
    assert_eq!(s, before);
    let mut s = Stack::new();
    s.serial = usize::MAX;
    let before = s.clone();
    assert!(s.call(10).is_err());
    assert_eq!(s, before);
}
