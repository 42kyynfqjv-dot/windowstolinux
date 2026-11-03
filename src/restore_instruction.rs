//! Shared validation of bounded original context-load and indirect-transfer effects.
use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic, OpKind, Register};
use std::collections::BTreeSet;
pub(crate) fn restore_body(code: &[u8], origin: u32) -> Result<String, String> {
    let mut decoder = Decoder::with_ip(32, code, u64::from(origin), DecoderOptions::NONE);
    let mut owner = None;
    let mut fields = BTreeSet::new();
    let mut source = String::new();
    let mut count = 0;
    while decoder.can_decode() {
        let i = decoder.decode();
        count += 1;
        if i.is_invalid()
            || count > 8
            || i.has_lock_prefix()
            || i.has_rep_prefix()
            || i.has_repne_prefix()
            || i.segment_prefix() != Register::None
            || i.memory_index() != Register::None
        {
            return Err("restore: instruction policy".into());
        }
        if i.mnemonic() == Mnemonic::Mov
            && i.op0_kind() == OpKind::Register
            && i.op1_kind() == OpKind::Memory
        {
            if owner.is_none() {
                if !matches!(i.op0_register(), Register::ECX | Register::EDX)
                    || i.memory_base() != Register::ESP
                    || i.memory_displacement32() != 4
                {
                    return Err("restore: saved context argument".into());
                }
                owner = Some(i.op0_register());
                continue;
            }
            if Some(i.memory_base()) != owner {
                return Err("restore: pointer ownership".into());
            }
            let (index, offset) = match i.op0_register() {
                Register::EAX => (0, 176),
                Register::ESP => (4, 196),
                Register::EBP => (5, 180),
                _ => return Err("restore: protected register".into()),
            };
            if i.memory_displacement32() != offset || !fields.insert(index) {
                return Err("restore: context field binding".into());
            }
            source.push_str(&format!("context[{index}]=view.read_saved({index})?;\n"));
        } else if i.mnemonic() == Mnemonic::Jmp
            && i.op0_kind() == OpKind::Memory
            && Some(i.memory_base()) == owner
            && i.memory_displacement32() == 184
            && i.code() == Code::Jmp_rm32
        {
            if decoder.can_decode() || fields != BTreeSet::from([0, 4, 5]) {
                return Err("restore: incomplete terminal transfer".into());
            }
            source.push_str("context[8]=view.read_saved(8)?;\nOk(())\n");
            return Ok(source);
        } else {
            return Err("restore: unsupported effect".into());
        }
    }
    Err("restore: missing transfer".into())
}
