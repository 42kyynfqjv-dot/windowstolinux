//! Independently implemented 32-bit arithmetic contracts; see SUB502-CONTRACT.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags {
    pub carry: bool,
    pub zero: bool,
    pub sign: bool,
    pub overflow: bool,
}
impl Flags {
    pub fn add(a: u32, b: u32) -> (u32, Self) {
        let (result, carry) = a.overflowing_add(b);
        (
            result,
            Self {
                carry,
                zero: result == 0,
                sign: result & 0x8000_0000 != 0,
                overflow: (!(a ^ b) & (a ^ result) & 0x8000_0000) != 0,
            },
        )
    }
    pub fn compare(a: u32, b: u32) -> Self {
        let result = a.wrapping_sub(b);
        Self {
            carry: a < b,
            zero: result == 0,
            sign: result & 0x8000_0000 != 0,
            overflow: ((a ^ b) & (a ^ result) & 0x8000_0000) != 0,
        }
    }
    pub fn xor_self() -> Self {
        Self {
            carry: false,
            zero: true,
            sign: false,
            overflow: false,
        }
    }
}
