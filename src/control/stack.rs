// Independently implemented bounded stack contract; see SUB507-DESIGN.md.
// Used by validation and embedded as Rust source in the generated application.
// No concrete ESP or readable numeric return address is represented.
use std::convert::TryFrom;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Word {
    Entry,
    Data {
        owner: usize,
        value: u32,
    },
    Return {
        frame: usize,
        parent: usize,
        next: usize,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stack {
    words: Vec<Word>,
    frame: usize,
    serial: usize,
    depth: usize,
    halted: bool,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Return {
    Resume(usize),
    Exit(u8),
}
impl Stack {
    pub fn new() -> Self {
        Self {
            words: vec![Word::Entry],
            frame: 0,
            serial: 0,
            depth: 0,
            halted: false,
        }
    }
    fn active(&self) -> Result<(), &'static str> {
        if self.halted {
            Err("stack execution already terminated")
        } else {
            Ok(())
        }
    }
    fn room(&self) -> Result<(), &'static str> {
        self.active()?;
        if self.words.len() >= 129 {
            Err("stack capacity limit exceeded")
        } else {
            Ok(())
        }
    }
    pub fn push(&mut self, value: u32) -> Result<(), &'static str> {
        self.room()?;
        self.words.push(Word::Data {
            owner: self.frame,
            value,
        });
        Ok(())
    }
    pub fn call(&mut self, next: usize) -> Result<(), &'static str> {
        self.room()?;
        if self.depth >= 32 {
            return Err("call nesting limit exceeded");
        }
        let frame = self
            .serial
            .checked_add(1)
            .ok_or("frame identity overflow")?;
        self.words.push(Word::Return {
            frame,
            parent: self.frame,
            next,
        });
        self.serial = frame;
        self.frame = frame;
        self.depth += 1;
        Ok(())
    }
    pub fn output_arguments(&mut self, next: usize) -> Result<[u32; 3], &'static str> {
        self.active()?;
        let start = self
            .words
            .len()
            .checked_sub(3)
            .ok_or("missing output arguments")?;
        let mut values = [0; 3];
        for (i, word) in self.words[start..].iter().enumerate() {
            match word {
                Word::Data { owner, value } if *owner == self.frame => values[i] = *value,
                _ => return Err("output argument ownership"),
            }
        }
        if values[2] != 1 || !(1..=64).contains(&values[0]) {
            return Err("output fd/count");
        }
        self.call(next)?;
        if self.ret(None)? != Return::Resume(next) {
            return Err("external return mismatch");
        }
        Ok(values)
    }
    pub fn argument(&self) -> Result<u32, &'static str> {
        self.active()?;
        match self.words.as_slice() {
            [.., Word::Data { owner, value }, Word::Return { frame, parent, .. }]
                if *frame == self.frame && owner == parent =>
            {
                Ok(*value)
            }
            _ => Err("argument is not caller data immediately below current return"),
        }
    }
    pub fn cleanup(&mut self) -> Result<(), &'static str> {
        self.active()?;
        match self.words.last() {
            Some(Word::Data { owner, .. }) if *owner == self.frame => {
                self.words.pop();
                Ok(())
            }
            _ => Err("cleanup would cross frame boundary"),
        }
    }
    pub fn ret(&mut self, eax: Option<u32>) -> Result<Return, &'static str> {
        self.active()?;
        match self.words.last().cloned() {
            Some(Word::Return {
                frame,
                parent,
                next,
            }) if frame == self.frame && self.depth > 0 => {
                self.words.pop();
                self.frame = parent;
                self.depth -= 1;
                Ok(Return::Resume(next))
            }
            Some(Word::Entry) if self.frame == 0 && self.depth == 0 && self.words.len() == 1 => {
                let value = u8::try_from(eax.ok_or("unknown return EAX")?)
                    .map_err(|_| "Windows exit status exceeds Linux's 8-bit exit range")?;
                self.halted = true;
                Ok(Return::Exit(value))
            }
            _ => Err("unbalanced return: data or foreign return above current frame"),
        }
    }
}

#[cfg(test)]
#[path = "stack_tests.rs"]
mod tests;
