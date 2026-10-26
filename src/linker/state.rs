// Shared checked transitions for validation and emitted native code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value {
    Integer(u32),
    Partial([Option<u8>; 4]),
    Pointer(u32),
    Unknown(u32),
}
impl Value {
    fn bytes(self) -> Result<[Option<u8>; 4], String> {
        match self {
            Self::Integer(v) => Ok(v.to_le_bytes().map(Some)),
            Self::Partial(b) => Ok(b),
            Self::Unknown(_) => Ok([None; 4]),
            Self::Pointer(_) => Err("pointer byte access".into()),
        }
    }
    fn from_bytes(b: [Option<u8>; 4]) -> Self {
        match b {
            [Some(a), Some(c), Some(d), Some(e)] => Self::Integer(u32::from_le_bytes([a, c, d, e])),
            _ => Self::Partial(b),
        }
    }

    fn integer(self) -> Result<u32, String> {
        if let Self::Integer(v) = self {
            Ok(v)
        } else {
            Err("scalar required".into())
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Knowledge {
    carry: Option<bool>,
    zero: Option<bool>,
    sign: Option<bool>,
    overflow: Option<bool>,
}
impl From<Flags> for Knowledge {
    fn from(f: Flags) -> Self {
        Self {
            carry: Some(f.carry),
            zero: Some(f.zero),
            sign: Some(f.sign),
            overflow: Some(f.overflow),
        }
    }
}
#[cfg(test)]
impl From<Option<Flags>> for Knowledge {
    fn from(f: Option<Flags>) -> Self {
        f.map(Self::from).unwrap_or_default()
    }
}
#[cfg(test)]
impl PartialEq<Option<Flags>> for Knowledge {
    fn eq(&self, f: &Option<Flags>) -> bool {
        *self == Self::from(*f)
    }
}
#[cfg(test)]
impl Knowledge {
    fn is_none(&self) -> bool {
        *self == Self::default()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Allocation {
    Words(usize),
    Bytes(usize),
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Word {
    Entry,
    Local(usize, usize, Option<u32>),
    Bytes(usize, usize, [Option<u8>; 4]),
    Data(usize, Value),
    Saved(usize, Value),
    Return(usize, u32),
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Frame {
    owner: usize,
    esi: Value,
    boundary: usize,
    allocation: Option<Allocation>,
}
#[derive(Clone, Copy, Debug)]
enum Op {
    PushEcx,
    PopEcx,
    StoreByte(u8, u8),
    StoreAl,
    LoadByteEax(u8),
    LoadByteEcx,
    IncAl,
    AllocateLocal,
    StoreLocalZero(u32),
    StoreFour(u32),
    AddLocalZero,
    Save,
    Restore,
    Push(u32),
    Pointer(u32),
    Write,
    MoveEsi,
    Mov(u32),
    Argument,
    ScalarArgumentTwo,
    EcxArgumentOne,
    EdxOne,
    CompareEcxEax,
    SelectGe,
    AddEcx,
    AddArgument,
    AddThirdArgument,
    Cleanup,
    CleanupSix,
    CleanupTwo,
    CompareEax(u32),
    CompareEsi(u32),
    Xor,
    CopyArgument,
    StoreSecond,
    Tail(u32),
    Equal(u32),
    Call(u32),
    Branch(u32),
    Ret,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct State {
    pc: u32,
    eax: Value,
    esi: Value,
    ecx: Value,
    edx: Value,
    flags: Knowledge,
    words: Vec<Word>,
    frames: Vec<Frame>,
    serial: usize,
    steps: usize,
    done: bool,
}
impl State {
    fn new(pc: u32) -> Self {
        Self {
            pc,
            eax: Value::Unknown(0),
            esi: Value::Unknown(1),
            ecx: Value::Unknown(2),
            edx: Value::Unknown(3),
            flags: Knowledge::default(),
            words: vec![Word::Entry],
            frames: vec![Frame {
                owner: 0,
                esi: Value::Unknown(1),
                boundary: 0,
                allocation: None,
            }],
            serial: 0,
            steps: 0,
            done: false,
        }
    }
    fn owner(&self) -> usize {
        self.frames.last().unwrap().owner
    }
    fn boundary(&self) -> Result<usize, String> {
        let frame = self.frames.last().ok_or("missing frame")?;
        let valid = if self.frames.len() == 1 {
            frame.boundary == 0 && self.words.get(frame.boundary) == Some(&Word::Entry)
        } else {
            matches!(self.words.get(frame.boundary), Some(Word::Return(o,_)) if *o == frame.owner)
        };
        if !valid {
            return Err("protected frame boundary".into());
        }
        Ok(frame.boundary)
    }
    fn local_window(&self) -> Result<usize, String> {
        let boundary = self.boundary()?;
        let token = self
            .frames
            .last()
            .unwrap()
            .allocation
            .ok_or("no local allocation")?;
        let Allocation::Words(token) = token else {
            return Err("word allocation required".into());
        };
        if self.words.len() != boundary + 3
            || !self.words[boundary + 1..]
                .iter()
                .all(|w| matches!(w, Word::Local(o,t,_) if *o == self.owner() && *t == token))
        {
            return Err("local ownership/shape".into());
        }
        Ok(boundary + 1)
    }
    fn byte_window(&self) -> Result<[Option<u8>; 4], String> {
        let at = self.boundary()?;
        let Some(Allocation::Bytes(token)) = self.frames.last().unwrap().allocation else {
            return Err("byte allocation required".into());
        };
        if self.words.len() != at + 2 {
            return Err("byte allocation shape".into());
        }
        match self.words.last() {
            Some(Word::Bytes(o, t, b)) if *o == self.owner() && *t == token => Ok(*b),
            _ => Err("byte ownership".into()),
        }
    }
    fn read_byte(&self, offset: u8) -> Result<u8, String> {
        if offset > 1 {
            return Err("byte offset".into());
        }
        self.byte_window()?[offset as usize].ok_or("unknown byte".into())
    }
    fn local_value(&self, at: usize) -> Result<u32, String> {
        match self.words.get(at) {
            Some(Word::Local(_, _, Some(v))) => Ok(*v),
            _ => Err("uninitialized local".into()),
        }
    }
    fn has_locals(&self) -> bool {
        self.frames.last().unwrap().allocation.is_some()
    }
    fn push(&mut self, w: Word) -> Result<(), String> {
        if self.words.len() >= 129 {
            return Err("stack limit".into());
        }
        self.words.push(w);
        Ok(())
    }
    fn argument(&self, index: usize) -> Result<Value, String> {
        if self.frames.len() < 2
            || !matches!(self.words.last(),Some(Word::Return(o,_)) if *o==self.owner())
        {
            return Err("argument return boundary".into());
        }
        let at = self
            .words
            .len()
            .checked_sub(index + 1)
            .ok_or("argument bounds")?;
        match self.words[at] {
            Word::Data(o, v) if o == self.frames[self.frames.len() - 2].owner => Ok(v),
            _ => Err("argument ownership".into()),
        }
    }
    fn return_boundary(&self) -> Result<usize, String> {
        if self.frames.len() < 2 {
            return Err("entry frame".into());
        }
        self.words
            .iter()
            .rposition(|w| matches!(w, Word::Return(o,_) if *o == self.owner()))
            .ok_or_else(|| "protected return".into())
    }
    fn scalar_at(&self, boundary: usize, at: usize) -> Result<u32, String> {
        if at >= boundary || boundary - at > 2 {
            return Err("argument range".into());
        }
        match self.words.get(at) {
            Some(Word::Data(o, v)) if *o == self.frames[self.frames.len() - 2].owner => v.integer(),
            _ => Err("argument ownership".into()),
        }
    }
    fn scalar_window(&self) -> Result<usize, String> {
        let boundary = self.return_boundary()?;
        if boundary + 1 != self.words.len() {
            return Err("unbalanced frame".into());
        }
        for index in 1..=2 {
            self.scalar_at(
                boundary,
                boundary.checked_sub(index).ok_or("argument bounds")?,
            )?;
        }
        Ok(boundary)
    }
    fn step(
        &mut self,
        op: Op,
        next: u32,
        output: &mut impl FnMut(u32, u32) -> Result<u32, String>,
    ) -> Result<Option<u32>, String> {
        let mut candidate = self.clone();
        let alternate = candidate.step_inner(op, next, output)?;
        *self = candidate;
        Ok(alternate)
    }
    fn step_inner(
        &mut self,
        op: Op,
        next: u32,
        output: &mut impl FnMut(u32, u32) -> Result<u32, String>,
    ) -> Result<Option<u32>, String> {
        if self.done || self.steps >= 1024 {
            return Err("terminal state or instruction limit".into());
        }
        self.boundary()?;
        if self.has_locals()
            && matches!(
                op,
                Op::Save
                    | Op::Restore
                    | Op::Push(_)
                    | Op::Pointer(_)
                    | Op::CopyArgument
                    | Op::StoreSecond
                    | Op::Tail(_)
                    | Op::Write
                    | Op::Cleanup
                    | Op::CleanupSix
                    | Op::Ret
            )
        {
            return Err("operation with live locals".into());
        }
        self.steps += 1;
        self.pc = next;
        match op {
            Op::PushEcx => {
                let at = self.boundary()?;
                if self.has_locals() || self.words.len() != at + 1 {
                    return Err("byte allocation shape".into());
                }
                let b = self.ecx.bytes()?;
                let token = self.steps;
                self.push(Word::Bytes(self.owner(), token, b))?;
                self.frames.last_mut().unwrap().allocation = Some(Allocation::Bytes(token));
            }
            Op::PopEcx => {
                self.ecx = Value::from_bytes(self.byte_window()?);
                self.words.pop();
                self.frames.last_mut().unwrap().allocation = None;
            }
            Op::StoreByte(offset, value) => {
                if offset > 1 {
                    return Err("byte offset".into());
                }
                let mut b = self.byte_window()?;
                b[offset as usize] = Some(value);
                let Some(Word::Bytes(_, _, bytes)) = self.words.last_mut() else {
                    unreachable!()
                };
                *bytes = b;
            }
            Op::StoreAl => {
                let value = self.eax.bytes()?[0].ok_or("unknown AL")?;
                let mut b = self.byte_window()?;
                b[1] = Some(value);
                let Some(Word::Bytes(_, _, bytes)) = self.words.last_mut() else {
                    unreachable!()
                };
                *bytes = b;
            }
            Op::LoadByteEax(offset) => {
                self.eax = Value::Integer(u32::from(self.read_byte(offset)?))
            }
            Op::LoadByteEcx => self.ecx = Value::Integer(u32::from(self.read_byte(1)?)),
            Op::IncAl => {
                let mut b = self.eax.bytes()?;
                let old = b[0].ok_or("unknown AL")?;
                let value = old.wrapping_add(1);
                b[0] = Some(value);
                self.eax = Value::from_bytes(b);
                self.flags.zero = Some(value == 0);
                self.flags.sign = Some(value & 128 != 0);
                self.flags.overflow = Some(old == 127);
            }
            Op::AllocateLocal => {
                let boundary = self.boundary()?;
                if self.has_locals() || self.words.len() != boundary + 1 {
                    return Err("local allocation shape".into());
                }
                if self.words.len() > 127 {
                    return Err("stack limit".into());
                }
                let token = self.steps;
                self.words.extend([
                    Word::Local(self.owner(), token, None),
                    Word::Local(self.owner(), token, None),
                ]);
                self.frames.last_mut().unwrap().allocation = Some(Allocation::Words(token));
                self.flags = Knowledge::default();
            }
            Op::StoreLocalZero(v) | Op::StoreFour(v)
                if self.has_locals() || matches!(op, Op::StoreLocalZero(_)) =>
            {
                let at = self.local_window()? + usize::from(matches!(op, Op::StoreLocalZero(_)));
                let Word::Local(_, _, value) = &mut self.words[at] else {
                    unreachable!()
                };
                *value = Some(v);
            }
            Op::StoreFour(v) => {
                if v != 12 {
                    return Err("unsupported caller store value".into());
                }
                let boundary = self.scalar_window()?;
                let owner = self.frames[self.frames.len() - 2].owner;
                self.words[boundary - 1] = Word::Data(owner, Value::Integer(12));
            }
            Op::StoreLocalZero(_) => unreachable!(),
            Op::AddLocalZero => {
                let at = self.local_window()? + 1;
                let (value, flags) = Flags::add(self.eax.integer()?, self.local_value(at)?);
                self.eax = Value::Integer(value);
                self.flags = Knowledge::from(flags);
            }
            Op::Save => self.push(Word::Saved(self.owner(), self.esi))?,
            Op::Restore => match self.words.last().cloned() {
                Some(Word::Saved(o, v)) if o == self.owner() => {
                    self.words.pop();
                    self.esi = v
                }
                _ => return Err("saved ESI ownership".into()),
            },
            Op::Push(v) => self.push(Word::Data(self.owner(), Value::Integer(v)))?,
            Op::Pointer(rva) => self.push(Word::Data(self.owner(), Value::Pointer(rva)))?,
            Op::Mov(v) => self.eax = Value::Integer(v),
            Op::MoveEsi => {
                if matches!(self.eax, Value::Partial(_)) {
                    return Err("partial ESI move".into());
                }
                self.esi = self.eax;
            }
            Op::Argument => {
                self.eax = if self.has_locals() {
                    Value::Integer(self.local_value(self.local_window()?)?)
                } else {
                    self.argument(1)?
                }
            }
            Op::ScalarArgumentTwo => self.eax = Value::Integer(self.argument(2)?.integer()?),
            Op::EcxArgumentOne => self.ecx = Value::Integer(self.argument(1)?.integer()?),
            Op::EdxOne => self.edx = Value::Integer(1),
            Op::CompareEcxEax => {
                self.flags =
                    Knowledge::from(Flags::compare(self.ecx.integer()?, self.eax.integer()?))
            }
            Op::SelectGe => {
                let sign = self.flags.sign.ok_or("unknown conditional flags")?;
                let overflow = self.flags.overflow.ok_or("unknown conditional flags")?;
                // Require both scalar operands even when the condition is false.
                // Requiring old EAX on true is a conservative subset restriction.
                self.eax.integer()?;
                let source = self.edx.integer()?;
                if sign == overflow {
                    self.eax = Value::Integer(source)
                }
            }
            Op::AddEcx => {
                let (value, flags) = Flags::add(self.eax.integer()?, self.ecx.integer()?);
                self.eax = Value::Integer(value);
                self.flags = Knowledge::from(flags)
            }
            Op::AddArgument | Op::AddThirdArgument => {
                let index = if matches!(op, Op::AddThirdArgument) {
                    3
                } else {
                    2
                };
                let (v, f) = Flags::add(self.eax.integer()?, self.argument(index)?.integer()?);
                self.eax = Value::Integer(v);
                self.flags = Knowledge::from(f)
            }
            Op::CompareEax(v) => {
                self.flags = Knowledge::from(Flags::compare(self.eax.integer()?, v))
            }
            Op::CompareEsi(v) => {
                self.flags = Knowledge::from(Flags::compare(self.esi.integer()?, v))
            }
            Op::Xor => {
                if matches!(self.eax, Value::Pointer(_)) {
                    return Err("pointer arithmetic".into());
                }
                self.eax = Value::Integer(0);
                self.flags = Knowledge::from(Flags::xor_self())
            }
            Op::CleanupTwo if self.has_locals() => {
                let at = self.local_window()?;
                self.words.truncate(at);
                self.frames.last_mut().unwrap().allocation = None;
                self.flags = Knowledge::default();
            }
            Op::Cleanup | Op::CleanupSix | Op::CleanupTwo => {
                let boundary = self.boundary()?;
                if self.words[boundary + 1..]
                    .iter()
                    .any(|w| matches!(w, Word::Local(..) | Word::Bytes(..)))
                {
                    return Err("untracked local allocation".into());
                }
                let count = match op {
                    Op::CleanupTwo => 2,
                    Op::CleanupSix => 6,
                    _ => 5,
                };
                let at = self
                    .words
                    .len()
                    .checked_sub(count)
                    .ok_or("cleanup bounds")?;
                if at <= boundary
                    || !self.words[at..]
                        .iter()
                        .all(|w| matches!(w,Word::Data(o,_) if *o==self.owner()))
                {
                    return Err("cleanup ownership".into());
                }
                self.words.truncate(at);
                self.flags = Knowledge::default()
            }
            Op::CopyArgument => {
                let boundary = self.return_boundary()?;
                let extra = self.words.len() - boundary - 1;
                if extra > 1
                    || !self.words[boundary + 1..]
                        .iter()
                        .all(|w| matches!(w,Word::Data(o,_) if *o==self.owner()))
                {
                    return Err("copy shape".into());
                }
                let at = self.words.len().checked_sub(3).ok_or("argument bounds")?;
                let value = self.scalar_at(boundary, at)?;
                self.push(Word::Data(self.owner(), Value::Integer(value)))?;
            }
            Op::StoreSecond => {
                let boundary = self.scalar_window()?;
                let owner = self.frames[self.frames.len() - 2].owner;
                self.words[boundary - 2] = Word::Data(owner, Value::Integer(3));
            }
            Op::Tail(target) => {
                self.scalar_window()?;
                if self.esi != self.frames.last().unwrap().esi {
                    return Err("ESI not restored".into());
                }
                // Static routine graph is acyclic; retain this frame/return unchanged.
                self.pc = target;
            }
            Op::Call(target) => {
                if self.frames.len() > 32 {
                    return Err("call depth".into());
                }
                match self.frames.last().unwrap().allocation {
                    Some(Allocation::Words(_)) => {
                        self.local_window()?;
                    }
                    Some(Allocation::Bytes(_)) => {
                        self.byte_window()?;
                    }
                    None => {}
                }
                let boundary = self.words.len();
                self.serial += 1;
                self.push(Word::Return(self.serial, next))?;
                self.frames.push(Frame {
                    owner: self.serial,
                    esi: self.esi,
                    boundary,
                    allocation: None,
                });
                self.pc = target
            }
            Op::Branch(target) | Op::Equal(target) => {
                let zero = self.flags.zero.ok_or("unknown branch flags")?;
                if zero == matches!(op, Op::Equal(_)) {
                    self.pc = target;
                    return Ok(Some(next));
                }
                return Ok(Some(target));
            }
            Op::Write => {
                if self.words.len() >= 129 || self.frames.len() > 32 {
                    return Err("external call limit".into());
                }
                let at = self.words.len().checked_sub(3).ok_or("output arguments")?;
                let args = &self.words[at..];
                let owner = self.owner();
                match args {
                    [Word::Data(a, Value::Integer(n)), Word::Data(b, Value::Pointer(rva)), Word::Data(c, Value::Integer(1))]
                        if *a == owner && *b == owner && *c == owner =>
                    {
                        self.eax = Value::Integer(output(*rva, *n)?);
                        self.flags = Knowledge::default();
                        // steps is unique along this path and bounded by 1024 above.
                        // Origins 0..3 name entry values; clones retain their identity.
                        self.ecx = Value::Unknown(4 + 2 * self.steps as u32);
                        self.edx = Value::Unknown(5 + 2 * self.steps as u32)
                    }
                    _ => return Err("typed output arguments".into()),
                }
            }
            Op::Ret => {
                if self.esi != self.frames.last().unwrap().esi {
                    return Err("ESI not restored".into());
                }
                let result = self.eax.integer()?;
                if self.frames.len() == 1 {
                    if self.words != [Word::Entry] || result > 255 {
                        return Err("entry return contract".into());
                    }
                    self.done = true
                } else {
                    match self.words.last().cloned() {
                        Some(Word::Return(o, pc)) if o == self.owner() => {
                            self.words.pop();
                            self.frames.pop();
                            self.pc = pc
                        }
                        _ => return Err("protected return".into()),
                    }
                }
            }
        }
        Ok(None)
    }
}
