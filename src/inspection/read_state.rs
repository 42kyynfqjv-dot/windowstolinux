// Same scalar transitions used for validation and native execution; no address API.
#[allow(dead_code)] // Individual proven programs may use only some IR forms.
#[derive(Clone, Copy, Debug)]
enum Op {
    Eax(u32),
    Ecx(u32),
    AddEax,
    AddEcx,
    Ret,
}
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Flags {
    cf: Option<bool>,
    zf: Option<bool>,
    sf: Option<bool>,
    of: Option<bool>,
}
fn execute(ops: &[Op]) -> std::result::Result<(u32, Flags), String> {
    let (mut eax, mut ecx) = (None, None);
    let mut flags = Flags::default();
    if ops.len() > 1024 {
        return Err("image reads: instruction cap".into());
    }
    for (i, op) in ops.iter().enumerate() {
        match *op {
            Op::Eax(v) => eax = Some(v),
            Op::Ecx(v) => ecx = Some(v),
            Op::AddEax | Op::AddEcx => {
                let a = eax.ok_or("image reads: unknown EAX")?;
                let b = ecx.ok_or("image reads: unknown ECX")?;
                let (v, carry) = a.overflowing_add(b);
                flags = Flags {
                    cf: Some(carry),
                    zf: Some(v == 0),
                    sf: Some(v & 0x80000000 != 0),
                    of: Some((!(a ^ b) & (a ^ v)) & 0x80000000 != 0),
                };
                if matches!(op, Op::AddEax) {
                    eax = Some(v);
                } else {
                    ecx = Some(v);
                }
            }
            Op::Ret => {
                if i + 1 != ops.len() {
                    return Err("image reads: code after return".into());
                }
                let v = eax.ok_or("image reads: unknown return")?;
                if v > 255 {
                    return Err("image reads: exit domain".into());
                }
                return Ok((v, flags));
            }
        }
    }
    Err("image reads: missing return".into())
}
