//! Native activation storage shared with generated code. This enforces lifecycle
//! mechanics, not guest exception semantics or emission eligibility.
use std::sync::atomic::{AtomicU64, Ordering};
static OWNERS: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    /// EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI. Unknown is never zero-filled.
    pub registers: [Option<u32>; 8],
    pub ip: Option<u32>,
    pub flags: Option<u32>,
}
impl Context {
    fn complete_integer(&self) -> bool {
        self.registers.iter().all(Option::is_some) && self.ip.is_some() && self.flags.is_some()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Id {
    owner: u64,
    generation: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Phase,
    Identity,
    UnknownContext,
    Budget,
    Noncontinuable,
}
pub struct Frame {
    pub id: Id,
    pub next: u32,
    pub stack_len: usize,
    pub saved: Context,
}
enum Phase {
    Normal,
    Search {
        captured: Context,
        continuable: bool,
    },
    Unwind {
        target: Id,
    },
    Restoration {
        captured: Context,
    },
    Blocked,
}
pub struct Stack {
    owner: u64,
    generation: u64,
    limit: usize,
    frames: Vec<Frame>,
    phase: Phase,
}
impl Stack {
    pub fn new(limit: usize) -> Result<Self, Error> {
        let mut owner = OWNERS.load(Ordering::Relaxed);
        loop {
            let next = owner.checked_add(1).ok_or(Error::Budget)?;
            match OWNERS.compare_exchange_weak(owner, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(current) => owner = current,
            }
        }
        Ok(Self {
            owner,
            generation: 0,
            limit,
            frames: Vec::new(),
            phase: Phase::Normal,
        })
    }
    fn normal(&self) -> Result<(), Error> {
        if matches!(self.phase, Phase::Normal) {
            Ok(())
        } else {
            Err(Error::Phase)
        }
    }
    pub fn top(&self) -> Option<&Frame> {
        self.frames.last()
    }
    pub fn push(&mut self, next: u32, stack_len: usize, saved: Context) -> Result<Id, Error> {
        self.normal()?;
        if self.frames.len() >= self.limit {
            return Err(Error::Budget);
        }
        self.generation = self.generation.checked_add(1).ok_or(Error::Budget)?;
        let id = Id {
            owner: self.owner,
            generation: self.generation,
        };
        self.frames.push(Frame {
            id,
            next,
            stack_len,
            saved,
        });
        Ok(id)
    }
    pub fn pop_normal(&mut self, id: Id) -> Result<Frame, Error> {
        self.normal()?;
        if self.top().map(|f| f.id) != Some(id) {
            return Err(Error::Identity);
        }
        Ok(self.frames.pop().unwrap())
    }
    /// Integer state only. Capturing this is not permission to execute a handler.
    pub fn begin_search(&mut self, captured: Context, continuable: bool) -> Result<(), Error> {
        self.normal()?;
        if !captured.complete_integer() {
            self.phase = Phase::Blocked;
            return Err(Error::UnknownContext);
        }
        self.phase = Phase::Search {
            captured,
            continuable,
        };
        Ok(())
    }
    pub fn select_unwind(&mut self, target: Id) -> Result<(), Error> {
        if !matches!(self.phase, Phase::Search { .. }) {
            return Err(Error::Phase);
        }
        if !self.frames.iter().any(|f| f.id == target) {
            return Err(Error::Identity);
        }
        self.phase = Phase::Unwind { target };
        Ok(())
    }
    /// The caller must execute the original cleanup while this frame is live.
    /// The selected activation is never returned for retirement.
    pub fn cleanup_frame(&self) -> Result<Option<&Frame>, Error> {
        let Phase::Unwind { target } = self.phase else {
            return Err(Error::Phase);
        };
        let top = self.top().ok_or(Error::Identity)?;
        Ok((top.id != target).then_some(top))
    }
    pub fn retire_cleaned(&mut self, id: Id) -> Result<Frame, Error> {
        if self.cleanup_frame()?.map(|f| f.id) != Some(id) {
            return Err(Error::Identity);
        }
        Ok(self.frames.pop().unwrap())
    }
    /// Preserve captured state for a same-instruction retry candidate. No guest
    /// context edits, target validation, memory restoration or normal-phase reset
    /// are authorized here; the future proof must supply those separately.
    pub fn retry_candidate(&mut self) -> Result<&Context, Error> {
        let Phase::Search {
            captured,
            continuable,
        } = &self.phase
        else {
            return Err(Error::Phase);
        };
        if !continuable {
            return Err(Error::Noncontinuable);
        }
        self.phase = Phase::Restoration {
            captured: captured.clone(),
        };
        let Phase::Restoration { captured } = &self.phase else {
            unreachable!()
        };
        Ok(captured)
    }
    pub fn block(&mut self) {
        self.phase = Phase::Blocked;
    }
}
