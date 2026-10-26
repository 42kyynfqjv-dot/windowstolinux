// Shared checked transitions for validation and emitted native code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value {
    Integer(u32),
    Pointer(u32),
    Unknown(u32),
}
impl Value {
    fn integer(self) -> Result<u32, String> {
        if let Self::Integer(v) = self {
            Ok(v)
        } else {
            Err("scalar required".into())
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Word {
    Entry,
    Data(usize, Value),
    Saved(usize, Value),
    Return(usize, u32),
}
#[derive(Clone, Debug)]
struct Frame {
    owner: usize,
    esi: Value,
}
#[derive(Clone, Copy, Debug)]
enum Op {
    Save,
    Restore,
    Push(u32),
    Pointer(u32),
    Write,
    MoveEsi,
    Mov(u32),
    Argument,
    AddArgument,
    Cleanup,
    CompareEax(u32),
    CompareEsi(u32),
    Xor,
    Call(u32),
    Branch(u32),
    Ret,
}
#[derive(Clone)]
struct State {
    pc: u32,
    eax: Value,
    esi: Value,
    flags: Option<Flags>,
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
            flags: None,
            words: vec![Word::Entry],
            frames: vec![Frame {
                owner: 0,
                esi: Value::Unknown(1),
            }],
            serial: 0,
            steps: 0,
            done: false,
        }
    }
    fn owner(&self) -> usize {
        self.frames.last().unwrap().owner
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
    fn step(
        &mut self,
        op: Op,
        next: u32,
        output: &mut impl FnMut(u32, u32) -> Result<u32, String>,
    ) -> Result<Option<u32>, String> {
        if self.done || self.steps >= 1024 {
            return Err("terminal state or instruction limit".into());
        }
        self.steps += 1;
        self.pc = next;
        match op {
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
            Op::MoveEsi => self.esi = self.eax,
            Op::Argument => self.eax = self.argument(1)?,
            Op::AddArgument => {
                let (v, f) = Flags::add(self.eax.integer()?, self.argument(2)?.integer()?);
                self.eax = Value::Integer(v);
                self.flags = Some(f)
            }
            Op::CompareEax(v) => self.flags = Some(Flags::compare(self.eax.integer()?, v)),
            Op::CompareEsi(v) => self.flags = Some(Flags::compare(self.esi.integer()?, v)),
            Op::Xor => {
                if matches!(self.eax, Value::Pointer(_)) {
                    return Err("pointer arithmetic".into());
                }
                self.eax = Value::Integer(0);
                self.flags = Some(Flags::xor_self())
            }
            Op::Cleanup => {
                let at = self.words.len().checked_sub(5).ok_or("cleanup bounds")?;
                if !self.words[at..]
                    .iter()
                    .all(|w| matches!(w,Word::Data(o,_) if *o==self.owner()))
                {
                    return Err("cleanup ownership".into());
                }
                self.words.truncate(at);
                self.flags = None
            }
            Op::Call(target) => {
                if self.frames.len() > 32 {
                    return Err("call depth".into());
                }
                self.serial += 1;
                self.push(Word::Return(self.serial, next))?;
                self.frames.push(Frame {
                    owner: self.serial,
                    esi: self.esi,
                });
                self.pc = target
            }
            Op::Branch(target) => {
                let zero = self.flags.ok_or("unknown branch flags")?.zero;
                if !zero {
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
                        self.flags = None
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
