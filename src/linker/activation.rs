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
    InvalidRestoration,
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
        event_generation: u64,
    },
    Unwind {
        target: Id,
        captured: Context,
    },
    Restoration {
        captured: Context,
    },
    Blocked,
}
pub struct Stack {
    owner: u64,
    generation: u64,
    event_generation: u64,
    limit: usize,
    frames: Vec<Frame>,
    phase: Phase,
}
/// Private lifecycle ticket, not a semantic proof. Only compiler-generated code
/// inside this module may compose it with a statically proved handler/target.
/// Keeping both the snapshot and identity private prevents external callers from
/// manufacturing a restoration request from an arbitrary CONTEXT.
struct OwnedEvent {
    owner: u64,
    generation: u64,
    activation: Id,
    captured: Context,
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
            event_generation: 0,
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
        let event_generation = self.event_generation.checked_add(1).ok_or(Error::Budget)?;
        self.event_generation = event_generation;
        self.phase = Phase::Search {
            captured,
            continuable,
            event_generation,
        };
        Ok(())
    }
    /// Called only by the emitted, proof-checked contained-resume wrapper. Normal
    /// helper clients cannot call this or commit an arbitrary context. A retry
    /// candidate from the public lifecycle API does not yield this ticket.
    fn capture_contained_resume(&self) -> Result<OwnedEvent, Error> {
        let Phase::Search {
            captured,
            continuable,
            event_generation,
        } = &self.phase
        else {
            return Err(Error::Phase);
        };
        if !continuable {
            return Err(Error::Noncontinuable);
        }
        let activation = self.top().ok_or(Error::Identity)?.id;
        Ok(OwnedEvent {
            owner: self.owner,
            generation: *event_generation,
            activation,
            captured: captured.clone(),
        })
    }
    /// Mechanical ownership checks for a compiler-proven ContinueExecution
    /// path. The private emitted caller supplies a continuation proved from the
    /// original instruction boundaries and runs original handler effects first.
    /// This operation neither selects unwind nor retires cleanup frames.
    fn commit_contained_resume(
        &mut self,
        event: OwnedEvent,
        restored: Context,
        continuation: u32,
    ) -> Result<Context, Error> {
        let Phase::Search {
            captured,
            continuable,
            event_generation,
        } = &self.phase
        else {
            return Err(Error::Phase);
        };
        if !continuable {
            return Err(Error::Noncontinuable);
        }
        if event.owner != self.owner
            || event.generation != *event_generation
            || self.top().map(|frame| frame.id) != Some(event.activation)
            || event.captured != *captured
        {
            return Err(Error::Identity);
        }
        if !restored.complete_integer() {
            return Err(Error::UnknownContext);
        }
        if restored.ip != Some(continuation)
            || restored.registers[4] != captured.registers[4]
            || restored.registers[5] != captured.registers[5]
            || restored.flags != captured.flags
        {
            return Err(Error::InvalidRestoration);
        }
        // All validations precede mutation: a rejected request leaves the live
        // event and every frame intact. No stack/owner state is silently rebuilt.
        self.phase = Phase::Normal;
        Ok(restored)
    }
    pub fn select_unwind(&mut self, target: Id) -> Result<(), Error> {
        let Phase::Search { captured, .. } = &self.phase else {
            return Err(Error::Phase);
        };
        if !self.frames.iter().any(|f| f.id == target) {
            return Err(Error::Identity);
        }
        self.phase = Phase::Unwind {
            target,
            captured: captured.clone(),
        };
        Ok(())
    }
    pub fn event_context(&self) -> Result<&Context, Error> {
        match &self.phase {
            Phase::Search { captured, .. }
            | Phase::Unwind { captured, .. }
            | Phase::Restoration { captured } => Ok(captured),
            _ => Err(Error::Phase),
        }
    }
    /// The caller must execute the original cleanup while this frame is live.
    /// The selected activation is never returned for retirement.
    pub fn cleanup_frame(&self) -> Result<Option<&Frame>, Error> {
        let Phase::Unwind { target, .. } = self.phase else {
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
            ..
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

#[cfg(test)]
mod tests {
    use super::*;

    fn captured() -> Context {
        Context {
            registers: [
                Some(10),
                Some(11),
                Some(12),
                Some(13),
                Some(0x8000),
                Some(0x8100),
                Some(16),
                Some(17),
            ],
            ip: Some(0x1000),
            flags: Some(0x202),
        }
    }
    fn resumed() -> Context {
        let mut context = captured();
        context.registers[0] = Some(42);
        context.ip = Some(0x1002);
        context
    }
    fn searching() -> Stack {
        let mut stack = Stack::new(4).unwrap();
        stack.push(0x2000, 8, captured()).unwrap();
        stack.begin_search(captured(), true).unwrap();
        stack
    }

    #[test]
    fn contained_resume_preserves_all_live_frames_and_returns_exact_context() {
        let mut stack = Stack::new(4).unwrap();
        let outer = stack.push(0x2000, 8, captured()).unwrap();
        let inner = stack.push(0x3000, 12, captured()).unwrap();
        stack.begin_search(captured(), true).unwrap();
        let event = stack.capture_contained_resume().unwrap();
        assert_eq!(event.activation, inner);
        assert_eq!(event.captured, captured());
        assert_eq!(
            stack.commit_contained_resume(event, resumed(), 0x1002),
            Ok(resumed())
        );
        assert_eq!(stack.frames.len(), 2);
        assert_eq!(stack.event_context(), Err(Error::Phase));
        assert_eq!(stack.cleanup_frame().err(), Some(Error::Phase));
        assert_eq!(stack.pop_normal(inner).unwrap().stack_len, 12);
        assert_eq!(stack.pop_normal(outer).unwrap().stack_len, 8);
    }

    #[test]
    fn resume_rejects_foreign_and_replayed_event_generations() {
        let first = searching();
        let mut second = searching();
        let foreign = first.capture_contained_resume().unwrap();
        assert_eq!(
            second.commit_contained_resume(foreign, resumed(), 0x1002),
            Err(Error::Identity)
        );
        assert_eq!(second.event_context(), Ok(&captured()));

        let stale = second.capture_contained_resume().unwrap();
        let current = second.capture_contained_resume().unwrap();
        second
            .commit_contained_resume(current, resumed(), 0x1002)
            .unwrap();
        // Same activation and identical context still constitute a new event.
        second.begin_search(captured(), true).unwrap();
        assert_eq!(
            second.commit_contained_resume(stale, resumed(), 0x1002),
            Err(Error::Identity)
        );
        assert_eq!(second.event_context(), Ok(&captured()));
        let valid = second.capture_contained_resume().unwrap();
        assert_eq!(
            second.commit_contained_resume(valid, resumed(), 0x1002),
            Ok(resumed())
        );
    }

    #[test]
    fn invalid_restoration_is_atomic_and_does_not_clear_pending_event() {
        let mut stack = searching();
        let original_id = stack.top().unwrap().id;
        for index in 0..10 {
            let mut missing = resumed();
            match index {
                0..=7 => missing.registers[index] = None,
                8 => missing.ip = None,
                _ => missing.flags = None,
            }
            let event = stack.capture_contained_resume().unwrap();
            assert_eq!(
                stack.commit_contained_resume(event, missing, 0x1002),
                Err(Error::UnknownContext)
            );
            assert_eq!(stack.event_context(), Ok(&captured()));
            assert_eq!(stack.top().unwrap().id, original_id);
        }
        for index in [4, 5, 8, 9] {
            let mut changed = resumed();
            match index {
                4 | 5 => changed.registers[index] = Some(0),
                8 => changed.ip = Some(0x1003),
                _ => changed.flags = Some(0),
            }
            let event = stack.capture_contained_resume().unwrap();
            assert_eq!(
                stack.commit_contained_resume(event, changed, 0x1002),
                Err(Error::InvalidRestoration)
            );
            assert_eq!(stack.event_context(), Ok(&captured()));
            assert_eq!(stack.top().unwrap().id, original_id);
        }
    }

    #[test]
    fn resume_rejects_unwind_retry_noncontinuable_and_empty_owner() {
        let mut stack = searching();
        let event = stack.capture_contained_resume().unwrap();
        let target = stack.top().unwrap().id;
        stack.select_unwind(target).unwrap();
        assert_eq!(stack.capture_contained_resume().err(), Some(Error::Phase));
        assert_eq!(
            stack.commit_contained_resume(event, resumed(), 0x1002),
            Err(Error::Phase)
        );
        assert_eq!(stack.cleanup_frame().unwrap().map(|frame| frame.id), None);

        let mut stack = searching();
        let event = stack.capture_contained_resume().unwrap();
        stack.retry_candidate().unwrap();
        assert_eq!(
            stack.commit_contained_resume(event, resumed(), 0x1002),
            Err(Error::Phase)
        );

        let mut stack = Stack::new(4).unwrap();
        stack.push(0x2000, 8, captured()).unwrap();
        stack.begin_search(captured(), false).unwrap();
        assert_eq!(
            stack.capture_contained_resume().err(),
            Some(Error::Noncontinuable)
        );
        let mut empty = Stack::new(4).unwrap();
        empty.begin_search(captured(), true).unwrap();
        assert_eq!(
            empty.capture_contained_resume().err(),
            Some(Error::Identity)
        );
    }

    #[test]
    fn exhausted_event_generation_cannot_reuse_old_identity() {
        let mut stack = Stack::new(1).unwrap();
        stack.push(0x2000, 8, captured()).unwrap();
        stack.event_generation = u64::MAX;
        assert_eq!(stack.begin_search(captured(), true), Err(Error::Budget));
        assert!(stack.normal().is_ok());
        assert_eq!(stack.event_generation, u64::MAX);
    }
}
