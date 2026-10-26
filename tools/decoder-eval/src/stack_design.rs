//! SUB-507 test-only executable design; NOT a production decoder or emulator.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Slot {
    Entry,
    Data {
        owner: usize,
        value: u32,
    },
    Return {
        frame: usize,
        parent: usize,
        pc: usize,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Model {
    slots: Vec<Slot>,
    halted: bool,
    frame: usize,
    serial: usize,
    depth: usize,
    eax: Option<u32>,
    flags: Option<[bool; 4]>,
}
impl Model {
    fn new() -> Self {
        Self {
            slots: vec![Slot::Entry],
            halted: false,
            frame: 0,
            serial: 0,
            depth: 0,
            eax: None,
            flags: None,
        }
    }
    fn active(&self) -> Result<(), &'static str> {
        if self.halted {
            Err("execution already terminated")
        } else {
            Ok(())
        }
    }
    fn room(&self) -> Result<(), &'static str> {
        self.active()?;
        if self.slots.len() >= 129 {
            Err("stack capacity")
        } else {
            Ok(())
        }
    }
    fn push(&mut self, value: u32) -> Result<(), &'static str> {
        self.room()?;
        self.slots.push(Slot::Data {
            owner: self.frame,
            value,
        });
        Ok(())
    }
    fn call(&mut self, pc: usize) -> Result<(), &'static str> {
        self.room()?;
        if self.depth >= 32 {
            return Err("call depth");
        }
        self.serial += 1;
        self.slots.push(Slot::Return {
            frame: self.serial,
            parent: self.frame,
            pc,
        });
        self.frame = self.serial;
        self.depth += 1;
        Ok(())
    }
    fn load_argument(&mut self) -> Result<(), &'static str> {
        self.active()?;
        match self.slots.as_slice() {
            [.., Slot::Data { owner, value }, Slot::Return { frame, parent, .. }]
                if *frame == self.frame && owner == parent =>
            {
                self.eax = Some(*value);
                Ok(())
            }
            _ => Err("argument is not caller data immediately below current return"),
        }
    }
    fn cleanup(&mut self) -> Result<(), &'static str> {
        self.active()?;
        match self.slots.last() {
            Some(Slot::Data { owner, .. }) if *owner == self.frame => {
                self.slots.pop();
                Ok(())
            }
            _ => Err("cleanup would cross frame boundary"),
        }
    }
    fn ret(&mut self) -> Result<Option<usize>, &'static str> {
        self.active()?;
        match self.slots.last().cloned() {
            Some(Slot::Return { frame, parent, pc }) if frame == self.frame => {
                self.slots.pop();
                self.frame = parent;
                self.depth -= 1;
                Ok(Some(pc))
            }
            Some(Slot::Entry) if self.frame == 0 && self.slots.len() == 1 => {
                if self.eax.is_none_or(|v| v > 255) {
                    return Err("entry exit unknown/out of range");
                }
                self.halted = true;
                Ok(None)
            }
            _ => Err("unbalanced return"),
        }
    }
}

#[test]
fn parameter_and_nested_ownership_trace() {
    let mut m = Model::new();
    m.flags = Some([true, false, true, false]);
    m.push(7).unwrap();
    m.call(10).unwrap();
    m.load_argument().unwrap();
    assert_eq!(m.eax, Some(7));
    assert_eq!(
        m.slots,
        vec![
            Slot::Entry,
            Slot::Data { owner: 0, value: 7 },
            Slot::Return {
                frame: 1,
                parent: 0,
                pc: 10
            }
        ]
    );
    m.push(11).unwrap();
    m.call(20).unwrap();
    m.load_argument().unwrap();
    assert_eq!(m.eax, Some(11));
    assert_eq!(m.ret(), Ok(Some(20)));
    m.cleanup().unwrap();
    m.load_argument().unwrap();
    assert_eq!(m.eax, Some(7));
    assert_eq!(m.ret(), Ok(Some(10)));
    m.cleanup().unwrap();
    assert_eq!(m.ret(), Ok(None));
    assert_eq!(m.flags, Some([true, false, true, false]));
}

#[test]
fn repeated_calls_read_each_callers_word() {
    let mut m = Model::new();
    for (word, continuation) in [(0x12345678, 10), (42, 20)] {
        m.push(word).unwrap();
        m.call(continuation).unwrap();
        m.load_argument().unwrap();
        assert_eq!(m.eax, Some(word));
        assert_eq!(m.ret(), Ok(Some(continuation)));
        m.cleanup().unwrap();
    }
    assert_eq!(m.ret(), Ok(None));
    assert_eq!(m.flags, None);
}

#[test]
fn rejects_return_addresses_missing_args_and_unbalanced_cleanup() {
    let mut m = Model::new();
    assert!(m.load_argument().is_err());
    assert!(m.cleanup().is_err());
    assert!(m.ret().is_err());
    m.call(10).unwrap(); // Word below return is entry sentinel, not an argument.
    assert!(m.load_argument().is_err());
    assert!(m.cleanup().is_err());
    m.call(20).unwrap(); // Word below return is another return address.
    assert!(m.load_argument().is_err());
    assert_eq!(m.ret(), Ok(Some(20)));
    m.push(9).unwrap(); // Data above current return cannot be returned through.
    let before = m.clone();
    assert!(m.ret().is_err());
    assert!(m.load_argument().is_err());
    assert_eq!(m, before);
    m.cleanup().unwrap();
    assert_eq!(m.ret(), Ok(Some(10)));
    m.push(8).unwrap();
    assert!(m.ret().is_err());
}

#[test]
fn capacity_and_depth_include_data_and_returns() {
    let mut m = Model::new();
    for _ in 0..127 {
        m.push(0).unwrap();
    }
    m.call(10).unwrap(); // 128 words below original ESP, plus entry sentinel.
    let before = m.clone();
    assert_eq!(m.push(0), Err("stack capacity"));
    assert_eq!(m, before);
    assert_eq!(m.call(20), Err("stack capacity"));
    assert_eq!(m.ret(), Ok(Some(10)));
    m.cleanup().unwrap();
    m.push(1).unwrap();
    let mut depth = Model::new();
    for pc in 0..32 {
        depth.call(pc).unwrap();
    }
    assert_eq!(depth.call(33), Err("call depth"));
}

#[test]
fn instruction_metadata_and_esp_flag_counterexample() {
    use iced_x86::{Code, Decoder, OpKind, Register};
    let push = Decoder::new(32, &[0x68, 0x78, 0x56, 0x34, 0x12], 0).decode();
    assert_eq!(push.code(), Code::Pushd_imm32);
    assert_eq!(push.immediate32(), 0x12345678);
    let load = Decoder::new(32, &[0x8b, 0x44, 0x24, 0x04], 0).decode();
    assert_eq!(load.code(), Code::Mov_r32_rm32);
    assert_eq!(load.op0_register(), Register::EAX);
    assert_eq!(load.op1_kind(), OpKind::Memory);
    assert_eq!(load.memory_base(), Register::ESP);
    assert_eq!(load.memory_index(), Register::None);
    assert_eq!(load.memory_displacement64(), 4);
    let lea = Decoder::new(32, &[0x8d, 0x64, 0x24, 0x04], 0).decode();
    assert_eq!(lea.code(), Code::Lea_r32_m);
    assert_eq!(lea.op0_register(), Register::ESP);
    assert_eq!(lea.memory_base(), Register::ESP);
    assert_eq!(lea.memory_displacement64(), 4);
    assert_eq!(lea.rflags_modified(), 0);
    assert_eq!(push.rflags_modified(), 0);
    assert_eq!(load.rflags_modified(), 0);
    let add = Decoder::new(32, &[0x83, 0xc4, 0x04], 0).decode();
    assert_ne!(add.rflags_modified(), 0);
    // ADD ESP,4 depends on unknown absolute ESP: two aligned, non-wrapping inputs.
    assert!(i64::from(0x7ffffffcu32 as i32) + 4 > i64::from(i32::MAX));
    assert!(i64::from(0x80000000u32 as i32) + 4 <= i64::from(i32::MAX));
    // Design acceptance is NOT production acceptance.
    for bytes in [
        &[0x68, 7, 0, 0, 0][..],
        &[0x8b, 0x44, 0x24, 4],
        &[0x8d, 0x64, 0x24, 4],
    ] {
        assert!(crate::control::decode_instruction(bytes, 0).is_err());
    }
}

#[test]
fn terminal_ownership_and_address_correspondence() {
    let mut m = Model::new();
    m.eax = Some(256);
    let before = m.clone();
    assert!(m.ret().is_err());
    assert_eq!(m, before);
    m.eax = Some(12);
    assert_eq!(m.ret(), Ok(None));
    let terminal = m.clone();
    assert!(m.push(7).is_err());
    assert!(m.call(10).is_err());
    assert!(m.load_argument().is_err());
    assert!(m.cleanup().is_err());
    assert!(m.ret().is_err());
    assert_eq!(m, terminal);

    // Invariant defenses: foreign-owned data cannot be discarded or read.
    let mut foreign = Model::new();
    foreign.slots.push(Slot::Data {
        owner: 99,
        value: 7,
    });
    let before = foreign.clone();
    assert!(foreign.cleanup().is_err());
    assert_eq!(foreign, before);
    foreign.call(10).unwrap();
    let before = foreign.clone();
    assert!(foreign.load_argument().is_err());
    assert_eq!(foreign, before);

    // Independent concrete byte layout for PUSH immediate / CALL / MOV / RET /
    // LEA cleanup. Concrete addresses exist only in this test oracle.
    for incoming in [0x1000u32, 0x7ffffffc, 0x80000000] {
        let mut memory = std::collections::BTreeMap::new();
        let mut esp = incoming;
        esp -= 4;
        for (i, byte) in 0x12345678u32.to_le_bytes().into_iter().enumerate() {
            memory.insert(esp + i as u32, byte);
        }
        esp -= 4;
        for (i, byte) in 0x00abcde0u32.to_le_bytes().into_iter().enumerate() {
            memory.insert(esp + i as u32, byte);
        }
        let loaded = u32::from_le_bytes(std::array::from_fn(|i| memory[&(esp + 4 + i as u32)]));
        let mut abstract_state = Model::new();
        abstract_state.push(0x12345678).unwrap();
        abstract_state.call(10).unwrap();
        abstract_state.load_argument().unwrap();
        assert_eq!(loaded, 0x12345678);
        assert_eq!(abstract_state.eax, Some(loaded));
        assert_eq!(esp, incoming - 4 * (abstract_state.slots.len() as u32 - 1));
        esp += 4;
        assert_eq!(abstract_state.ret(), Ok(Some(10)));
        assert_eq!(esp, incoming - 4 * (abstract_state.slots.len() as u32 - 1));
        esp += 4;
        abstract_state.cleanup().unwrap();
        assert_eq!(esp, incoming);
        assert_eq!(abstract_state.slots, vec![Slot::Entry]);
    }
}
