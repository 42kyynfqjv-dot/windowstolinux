//! Private lifecycle storage included beside compiler-proven original blocks.
//! This module alone is not a Windows dispatcher or an admission certificate.
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};
static OWNERS: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Error {
    Phase,
    Identity,
    Order,
    Range,
    Uninitialized,
    Budget,
    Restoration,
    Cleanup,
}

struct Scope {
    scope: u32,
    action: u32,
}
struct FrameSpec {
    /// Required scopes in original inner-to-outer execution order. Only the
    /// compiler's validated scope-data proof may construct this list.
    scopes: Vec<Scope>,
}
struct FrameInput {
    cells: Vec<Option<u32>>,
    context: [u32; 10],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FrameId {
    owner: u64,
    generation: u64,
}
struct Frame {
    id: FrameId,
    cells: Vec<Option<u32>>,
    context: [u32; 10],
    scopes: Vec<Scope>,
    cursor: usize,
    live: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Request {
    owner: u64,
    event: u64,
    frame: FrameId,
    cursor: usize,
    scope: u32,
    action: u32,
}
impl Request {
    fn action(self) -> u32 {
        self.action
    }
}
/// Constructed only inside execute_cleanup after original code succeeds.
struct Completion(Request);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Cleanup,
    Executing,
    Restore,
    Restoring,
    Done,
    Blocked,
}
struct Machine {
    owner: u64,
    // One event per Machine. A second event must obtain a fresh global owner;
    // neither Done nor Blocked can transition back to Cleanup. This is not a
    // persistent Windows thread identity or a reusable thread event counter.
    event: u64,
    frames: Vec<Frame>,
    selected: usize,
    current: usize,
    trace: Option<u32>,
    context: [u32; 10],
    phase: Phase,
    owned_storage: bool,
}

/// Private token attached once to the external image occupying this exact frame
/// slot. Reusing an index supplied by the lease instead of this stored binding
/// does not establish storage identity. Guest instructions cannot create tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OwnedFrameBinding {
    owner: u64,
    frame: FrameId,
    index: usize,
}
impl OwnedFrameBinding {
    fn owner(self) -> u64 {
        self.owner
    }
    fn frame_index(self) -> usize {
        self.index
    }
}

/// A scoped authority to execute original effects on one bound external image.
/// It cannot be retained after the closure or issue its own completion receipt.
struct OwnedLease<'a> {
    binding: OwnedFrameBinding,
    scope: Option<u32>,
    action: Option<u32>,
    fault: &'a Cell<Option<Error>>,
    bound: &'a Cell<bool>,
}
impl OwnedLease<'_> {
    fn owner(&self) -> u64 {
        self.binding.owner
    }
    fn frame_index(&self) -> usize {
        self.binding.index
    }
    fn scope(&self) -> Option<u32> {
        self.scope
    }
    fn action(&self) -> Option<u32> {
        self.action
    }
    fn fail<T>(&self, error: Error) -> Result<T, Error> {
        if self.fault.get().is_none() {
            self.fault.set(Some(error));
        }
        Err(self.fault.get().unwrap())
    }
    fn available(&self) -> Result<(), Error> {
        match self.fault.get() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    /// Verify the complete private token stored with the actual image. Guest
    /// integers or an index echoed from this lease are not storage authority.
    fn bind_storage(&mut self, binding: OwnedFrameBinding) -> Result<(), Error> {
        self.bind(binding)
    }
    fn bind(&mut self, binding: OwnedFrameBinding) -> Result<(), Error> {
        self.available()?;
        if binding != self.binding {
            return self.fail(Error::Identity);
        }
        self.bound.set(true);
        Ok(())
    }
    /// Execute an external-memory operation only while this lease is valid.
    /// A propagated or ignored failure becomes sticky; prior direct writes are
    /// retained and subsequent operations are not invoked.
    fn perform<T>(&mut self, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        self.available()?;
        if !self.bound.get() {
            return self.fail(Error::Identity);
        }
        match operation() {
            Ok(value) => Ok(value),
            Err(error) => self.fail(error),
        }
    }
}
struct OwnedTrace<'a> {
    value: &'a mut Option<u32>,
    fault: &'a Cell<Option<Error>>,
    bound: &'a Cell<bool>,
}
impl OwnedTrace<'_> {
    fn fail<T>(&self, error: Error) -> Result<T, Error> {
        if self.fault.get().is_none() {
            self.fault.set(Some(error));
        }
        Err(self.fault.get().unwrap())
    }
    fn available(&self) -> Result<(), Error> {
        if let Some(error) = self.fault.get() {
            return Err(error);
        }
        if !self.bound.get() {
            return self.fail(Error::Identity);
        }
        Ok(())
    }
    fn read(&mut self) -> Result<u32, Error> {
        self.available()?;
        match *self.value {
            Some(value) => Ok(value),
            None => self.fail(Error::Uninitialized),
        }
    }
    fn write(&mut self, value: u32) -> Result<(), Error> {
        self.available()?;
        *self.value = Some(value);
        Ok(())
    }
}

/// Borrowed while its exact frame is live; cannot access another frame, scope
/// cursor, phase or receipt constructor. Trace is a separate owned cell.
struct View<'a> {
    cells: &'a mut [Option<u32>],
    trace: &'a mut Option<u32>,
    saved: &'a [u32; 10],
    fault: &'a mut Option<Error>,
    read_only: bool,
}
impl View<'_> {
    fn available(&self) -> Result<(), Error> {
        match *self.fault {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.fault.get_or_insert(error);
        Err(error)
    }
    fn word_index(&mut self, offset: u32) -> Result<usize, Error> {
        self.available()?;
        let index = (offset / 4) as usize;
        if offset % 4 != 0 || index >= self.cells.len() {
            return self.fail(Error::Range);
        }
        Ok(index)
    }
    fn read_word(&mut self, offset: u32) -> Result<u32, Error> {
        let index = self.word_index(offset)?;
        match self.cells[index] {
            Some(value) => Ok(value),
            None => self.fail(Error::Uninitialized),
        }
    }
    fn write_word(&mut self, offset: u32, value: u32) -> Result<(), Error> {
        self.available()?;
        if self.read_only {
            return self.fail(Error::Restoration);
        }
        let index = self.word_index(offset)?;
        self.cells[index] = Some(value);
        Ok(())
    }
    fn read_trace(&mut self) -> Result<u32, Error> {
        self.available()?;
        match *self.trace {
            Some(value) => Ok(value),
            None => self.fail(Error::Uninitialized),
        }
    }
    fn write_trace(&mut self, value: u32) -> Result<(), Error> {
        self.available()?;
        if self.read_only {
            return self.fail(Error::Restoration);
        }
        *self.trace = Some(value);
        Ok(())
    }
    fn read_saved(&mut self, index: usize) -> Result<u32, Error> {
        self.available()?;
        match self.saved.get(index) {
            Some(value) => Ok(*value),
            None => self.fail(Error::Range),
        }
    }
}

impl Machine {
    fn new(
        specs: Vec<FrameSpec>,
        inputs: Vec<FrameInput>,
        selected: usize,
        trace: Option<u32>,
    ) -> Result<Self, Error> {
        if inputs.is_empty()
            || inputs.len() > 64
            || inputs.len() != specs.len()
            || selected >= inputs.len()
        {
            return Err(Error::Budget);
        }
        let mut scopes = 0usize;
        for (spec, input) in specs.iter().zip(&inputs) {
            scopes = scopes.checked_add(spec.scopes.len()).ok_or(Error::Budget)?;
            if scopes > 256 || input.cells.len() > 256 {
                return Err(Error::Budget);
            }
            for (index, scope) in spec.scopes.iter().enumerate() {
                if spec.scopes[..index]
                    .iter()
                    .any(|previous| previous.scope == scope.scope)
                {
                    return Err(Error::Order);
                }
            }
        }
        let mut owner = OWNERS.load(Ordering::Relaxed);
        loop {
            let next = owner.checked_add(1).ok_or(Error::Budget)?;
            match OWNERS.compare_exchange_weak(owner, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(actual) => owner = actual,
            }
        }
        let current = inputs.len() - 1;
        let context = inputs[current].context;
        let frames = specs
            .into_iter()
            .zip(inputs)
            .enumerate()
            .map(|(index, (spec, input))| Frame {
                id: FrameId {
                    owner,
                    generation: index as u64 + 1,
                },
                cells: input.cells,
                context: input.context,
                scopes: spec.scopes,
                cursor: 0,
                live: true,
            })
            .collect();
        let mut machine = Self {
            owner,
            event: 1,
            frames,
            selected,
            current,
            trace,
            context,
            phase: Phase::Cleanup,
            owned_storage: false,
        };
        machine.advance_completed_frames();
        Ok(machine)
    }
    /// Connected mode stores no second copy of image cells or saved CONTEXT.
    /// Original frame initialization, landing and context stores operate on the
    /// external images; this machine owns only lifecycle and cleanup receipts.
    fn new_owned(
        specs: Vec<FrameSpec>,
        selected: usize,
        current: [u32; 10],
        trace: Option<u32>,
    ) -> Result<Self, Error> {
        let inputs = specs
            .iter()
            .map(|_| FrameInput {
                cells: Vec::new(),
                context: [0; 10],
            })
            .collect();
        let mut machine = Self::new(specs, inputs, selected, trace)?;
        machine.context = current;
        machine.owned_storage = true;
        Ok(machine)
    }
    fn owner(&self) -> u64 {
        self.owner
    }
    /// Bind each original external image once while constructing the private
    /// adapter. A lease still checks that binding and its current lifetime.
    fn owned_binding(&self, index: usize) -> Result<OwnedFrameBinding, Error> {
        if !self.owned_storage {
            return Err(Error::Identity);
        }
        let frame = self.frames.get(index).ok_or(Error::Range)?;
        Ok(OwnedFrameBinding {
            owner: self.owner,
            frame: frame.id,
            index,
        })
    }
    fn binding(&self, index: usize) -> Result<OwnedFrameBinding, Error> {
        self.owned_binding(index)
    }
    fn reject<T>(&mut self, error: Error) -> Result<T, Error> {
        self.phase = Phase::Blocked;
        Err(error)
    }
    fn advance_completed_frames(&mut self) {
        while self.frames[self.current].cursor == self.frames[self.current].scopes.len() {
            if self.current == self.selected {
                self.phase = Phase::Restore;
                return;
            }
            // An abandoned frame loses its lifetime only after its final required
            // scope completed. Selected and older frames retain their cells.
            self.frames[self.current].live = false;
            self.current -= 1;
        }
    }
    fn next_cleanup(&self) -> Result<Option<Request>, Error> {
        if self.phase == Phase::Restore {
            return Ok(None);
        }
        if self.phase != Phase::Cleanup {
            return Err(Error::Phase);
        }
        let frame = &self.frames[self.current];
        let scope = &frame.scopes[frame.cursor];
        Ok(Some(Request {
            owner: self.owner,
            event: self.event,
            frame: frame.id,
            cursor: frame.cursor,
            scope: scope.scope,
            action: scope.action,
        }))
    }
    fn execute_cleanup(
        &mut self,
        request: Request,
        original: impl FnOnce(&mut View<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if self.owned_storage {
            return self.reject(Error::Identity);
        }
        let expected = match self.next_cleanup() {
            Ok(Some(value)) => value,
            _ => return self.reject(Error::Phase),
        };
        if request.owner != self.owner
            || request.event != self.event
            || request.frame != expected.frame
        {
            return self.reject(Error::Identity);
        }
        if request != expected {
            return self.reject(Error::Order);
        }
        self.phase = Phase::Executing;
        let frame = &mut self.frames[self.current];
        let mut fault = None;
        let result = original(&mut View {
            cells: &mut frame.cells,
            trace: &mut self.trace,
            saved: &frame.context,
            fault: &mut fault,
            read_only: false,
        });
        if let Some(error) = fault.or_else(|| result.err()) {
            // Preserve partial original effects. No receipt, retirement, retry,
            // rollback or restoration is allowed following an unhandled fault.
            return self.reject(error);
        }
        self.complete(Completion(request))
    }
    fn execute_owned_cleanup(
        &mut self,
        request: Request,
        original: impl FnOnce(&mut OwnedLease<'_>, &mut OwnedTrace<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if !self.owned_storage {
            return self.reject(Error::Identity);
        }
        let expected = match self.next_cleanup() {
            Ok(Some(expected)) => expected,
            _ => return self.reject(Error::Phase),
        };
        if request.owner != self.owner
            || request.event != self.event
            || request.frame != expected.frame
        {
            return self.reject(Error::Identity);
        }
        if request != expected {
            return self.reject(Error::Order);
        }
        if !self.frames[self.current].live {
            return self.reject(Error::Identity);
        }
        let binding = self.owned_binding(self.current)?;
        self.phase = Phase::Executing;
        let fault = Cell::new(None);
        let bound = Cell::new(false);
        let result = original(
            &mut OwnedLease {
                binding,
                scope: Some(request.scope),
                action: Some(request.action),
                fault: &fault,
                bound: &bound,
            },
            &mut OwnedTrace {
                value: &mut self.trace,
                fault: &fault,
                bound: &bound,
            },
        );
        if let Some(error) = fault.get().or_else(|| result.err()) {
            return self.reject(error);
        }
        if !bound.get() {
            return self.reject(Error::Identity);
        }
        self.complete(Completion(request))
    }
    fn complete(&mut self, receipt: Completion) -> Result<(), Error> {
        if self.phase != Phase::Executing {
            return self.reject(Error::Phase);
        }
        let request = receipt.0;
        let frame = &mut self.frames[self.current];
        let scope = &frame.scopes[frame.cursor];
        if request.owner != self.owner
            || request.event != self.event
            || request.frame != frame.id
            || request.cursor != frame.cursor
            || request.scope != scope.scope
            || request.action != scope.action
            || !frame.live
        {
            return self.reject(Error::Identity);
        }
        frame.cursor += 1;
        self.phase = Phase::Cleanup;
        self.advance_completed_frames();
        Ok(())
    }
    fn restore(
        &mut self,
        target: u32,
        original: impl FnOnce(&mut View<'_>, &mut [u32; 10]) -> Result<(), Error>,
    ) -> Result<[u32; 10], Error> {
        if self.owned_storage {
            return self.reject(Error::Identity);
        }
        if self.phase != Phase::Restore
            || self.current != self.selected
            || !self.frames[self.selected].live
        {
            return self.reject(Error::Phase);
        }
        self.phase = Phase::Restoring;
        let frame = &mut self.frames[self.selected];
        let mut context = self.context;
        let mut fault = None;
        let result = original(
            &mut View {
                cells: &mut frame.cells,
                trace: &mut self.trace,
                saved: &frame.context,
                fault: &mut fault,
                read_only: true,
            },
            &mut context,
        );
        if let Some(error) = fault.or_else(|| result.err()) {
            return self.reject(error);
        }
        let saved = frame.context;
        if saved[8] != target
            || context[8] != target
            || context[0] != saved[0]
            || context[4] != saved[4]
            || context[5] != saved[5]
            || [3, 6, 7].iter().any(|&i| context[i] != self.context[i])
        {
            return self.reject(Error::Restoration);
        }
        self.context = context;
        self.phase = Phase::Done;
        // ECX/EDX/flags in this bookkeeping array are not preserved guest state.
        // The emitted observation boundary must mark them unknown after cleanup
        // and the original restore helper. Only proved fields may be observed.
        Ok(context)
    }
    fn restore_owned(
        &mut self,
        target: u32,
        original: impl FnOnce(
            &mut OwnedLease<'_>,
            [Option<u32>; 10],
        ) -> Result<[Option<u32>; 10], Error>,
    ) -> Result<[Option<u32>; 10], Error> {
        if !self.owned_storage {
            return self.reject(Error::Identity);
        }
        if self.phase != Phase::Restore
            || self.current != self.selected
            || !self.frames[self.selected].live
        {
            return self.reject(Error::Phase);
        }
        let binding = self.owned_binding(self.selected)?;
        self.phase = Phase::Restoring;
        let fault = Cell::new(None);
        let bound = Cell::new(false);
        let mut current = self.context.map(Some);
        for index in [1, 2, 9] {
            current[index] = None;
        }
        let result = original(
            &mut OwnedLease {
                binding,
                scope: None,
                action: None,
                fault: &fault,
                bound: &bound,
            },
            current,
        );
        if let Some(error) = fault.get() {
            return self.reject(error);
        }
        let result = match result {
            Ok(result) => result,
            Err(error) => return self.reject(error),
        };
        if !bound.get() {
            return self.reject(Error::Identity);
        }
        // The actual original landing/context-preparation proof must establish
        // these values from the selected image. No external saved array grants
        // authority here, and unknown fields are never promoted to zero.
        if result[8] != Some(target)
            || [0, 4, 5].iter().any(|&index| result[index].is_none())
            || [1, 2, 9].iter().any(|&index| result[index].is_some())
            || [3, 6, 7]
                .iter()
                .any(|&index| result[index].is_some_and(|value| value != self.context[index]))
        {
            return self.reject(Error::Restoration);
        }
        for (index, value) in result.iter().enumerate() {
            if let Some(value) = value {
                self.context[index] = *value;
            }
        }
        self.phase = Phase::Done;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine() -> Machine {
        let specs = vec![
            FrameSpec { scopes: vec![] },
            FrameSpec {
                scopes: vec![Scope {
                    scope: 2,
                    action: 2,
                }],
            },
            FrameSpec {
                scopes: vec![
                    Scope {
                        scope: 0,
                        action: 0,
                    },
                    Scope {
                        scope: 1,
                        action: 1,
                    },
                ],
            },
        ];
        let inputs = (0..3)
            .map(|i| FrameInput {
                cells: vec![Some(i + 1), None],
                context: [
                    10 + i,
                    11,
                    12,
                    13 + i,
                    0x8000 + i * 16,
                    0x8100 + i * 16,
                    16 + i,
                    17 + i,
                    0x9000 + i * 16,
                    0x202,
                ],
            })
            .collect();
        Machine::new(specs, inputs, 0, Some(0)).unwrap()
    }
    fn execute_next(machine: &mut Machine) {
        let request = machine.next_cleanup().unwrap().unwrap();
        let digit = request.action() + 1;
        machine
            .execute_cleanup(request, |view| {
                let trace = view.read_trace()?;
                view.write_trace(trace * 10 + digit)?;
                let value = view.read_word(0)?;
                view.write_word(0, value + digit * 10)
            })
            .unwrap();
    }
    fn restore(view: &mut View<'_>, context: &mut [u32; 10]) -> Result<(), Error> {
        for index in [0, 4, 5, 8] {
            context[index] = view.read_saved(index)?;
        }
        Ok(())
    }
    #[test]
    fn original_cleanup_order_keeps_storage_live_until_last_scope() {
        let mut machine = machine();
        let selected = machine.frames[0].id;
        execute_next(&mut machine);
        assert_eq!(machine.trace, Some(1));
        assert!(machine.frames[2].live);
        assert_eq!(machine.frames[2].cursor, 1);
        execute_next(&mut machine);
        assert_eq!(machine.trace, Some(12));
        assert!(!machine.frames[2].live);
        assert!(machine.frames[1].live);
        execute_next(&mut machine);
        assert_eq!(machine.trace, Some(123));
        assert!(!machine.frames[1].live);
        assert!(machine.frames[0].live);
        assert_eq!(machine.frames[0].id, selected);
        assert_eq!(machine.frames[0].cells, vec![Some(1), None]);
        assert_eq!(machine.frames[1].cells, vec![Some(32), None]);
        assert_eq!(machine.frames[2].cells, vec![Some(33), None]);
        assert_eq!(machine.next_cleanup(), Ok(None));
        let restored = machine.restore(0x9000, restore).unwrap();
        assert_eq!(
            [restored[0], restored[4], restored[5], restored[8]],
            [10, 0x8000, 0x8100, 0x9000]
        );
        assert_eq!([restored[3], restored[6], restored[7]], [15, 18, 19]);
        assert_eq!(machine.restore(0x9000, restore), Err(Error::Phase));
    }
    #[test]
    fn foreign_replayed_skipped_and_forged_requests_block_without_running_code() {
        let a = machine();
        let mut b = machine();
        let foreign = a.next_cleanup().unwrap().unwrap();
        assert_eq!(
            b.execute_cleanup(foreign, |_| panic!("foreign code ran")),
            Err(Error::Identity)
        );
        assert_eq!(b.phase, Phase::Blocked);
        assert_eq!(b.frames[2].cursor, 0);
        assert_eq!(b.trace, Some(0));

        for field in 0..4 {
            let mut m = machine();
            let mut forged = m.next_cleanup().unwrap().unwrap();
            match field {
                0 => forged.cursor += 1,
                1 => forged.scope += 1,
                2 => forged.action += 1,
                _ => forged.event += 1,
            }
            assert!(m
                .execute_cleanup(forged, |_| panic!("forged code ran"))
                .is_err());
            assert_eq!(m.phase, Phase::Blocked);
            assert!(m.frames[2].live);
        }
        let mut m = machine();
        let stale = m.next_cleanup().unwrap().unwrap();
        execute_next(&mut m);
        assert_eq!(
            m.execute_cleanup(stale, |_| panic!("replayed code ran")),
            Err(Error::Order)
        );
        assert_eq!(m.trace, Some(1));
        assert_eq!(m.frames[2].cursor, 1);
        assert!(m.frames[2].live);
    }
    #[test]
    fn failed_cleanup_preserves_partial_effects_but_cannot_retire_or_restore() {
        let mut m = machine();
        let request = m.next_cleanup().unwrap().unwrap();
        assert_eq!(
            m.execute_cleanup(request, |view| {
                view.write_word(0, 42)?;
                view.write_trace(17)?;
                Err(Error::Cleanup)
            }),
            Err(Error::Cleanup)
        );
        assert_eq!(m.frames[2].cells[0], Some(42));
        assert_eq!(m.trace, Some(17));
        assert_eq!(m.frames[2].cursor, 0);
        assert!(m.frames[2].live);
        assert_eq!(m.phase, Phase::Blocked);
        assert_eq!(m.restore(0x9000, restore), Err(Error::Phase));
        assert_eq!(
            m.execute_cleanup(request, |_| panic!("failure retried")),
            Err(Error::Phase)
        );
    }
    #[test]
    fn ignored_memory_fault_is_sticky_and_complete_word_bounds_are_checked() {
        for offset in [1, 4, 8, u32::MAX] {
            let mut m = machine();
            let request = m.next_cleanup().unwrap().unwrap();
            let expected = if offset == 4 {
                Error::Uninitialized
            } else {
                Error::Range
            };
            assert_eq!(
                m.execute_cleanup(request, |view| {
                    view.write_trace(7)?;
                    let _ = view.read_word(offset);
                    // Later effects after an ignored fault must stay blocked.
                    assert_eq!(view.write_trace(99), Err(expected));
                    Ok(())
                }),
                Err(expected)
            );
            assert_eq!(m.trace, Some(7));
            assert_eq!(m.frames[2].cursor, 0);
            assert!(m.frames[2].live);
            assert_eq!(m.phase, Phase::Blocked);
        }
    }
    #[test]
    fn restoration_requires_finished_cleanup_and_original_target_effects() {
        let mut early = machine();
        assert_eq!(early.restore(0x9000, restore), Err(Error::Phase));
        assert!(early.frames.iter().all(|frame| frame.live));
        for corruption in 0..5 {
            let mut m = machine();
            for _ in 0..3 {
                execute_next(&mut m);
            }
            let before = m.context;
            let result = m.restore(0x9000, |view, context| {
                restore(view, context)?;
                match corruption {
                    0 => context[4] += 4,
                    1 => context[5] += 4,
                    2 => context[8] += 1,
                    3 => context[3] = 0,
                    _ => {
                        let _ = view.write_trace(99);
                    }
                }
                Ok(())
            });
            assert_eq!(result, Err(Error::Restoration));
            assert_eq!(m.context, before);
            assert_eq!(m.trace, Some(123));
            assert!(m.frames[0].live);
            assert_eq!(m.phase, Phase::Blocked);
        }
    }
    #[test]
    fn selected_frame_scopes_execute_without_retiring_selected_or_older_frames() {
        let specs = vec![
            FrameSpec { scopes: vec![] },
            FrameSpec {
                scopes: vec![Scope {
                    scope: 7,
                    action: 9,
                }],
            },
        ];
        let input = || FrameInput {
            cells: vec![Some(5)],
            context: [0; 10],
        };
        let mut m = Machine::new(specs, vec![input(), input()], 1, Some(0)).unwrap();
        execute_next(&mut m);
        assert!(m.frames.iter().all(|frame| frame.live));
        assert_eq!(m.frames[0].cells[0], Some(5));
        assert_eq!(m.frames[1].cells[0], Some(105));
        assert_eq!(m.phase, Phase::Restore);
    }
    #[test]
    fn malformed_plan_and_resource_budgets_reject_before_execution() {
        assert!(matches!(
            Machine::new(vec![], vec![], 0, None),
            Err(Error::Budget)
        ));
        let input = || FrameInput {
            cells: vec![],
            context: [0; 10],
        };
        let repeated = FrameSpec {
            scopes: vec![
                Scope {
                    scope: 1,
                    action: 1,
                },
                Scope {
                    scope: 1,
                    action: 2,
                },
            ],
        };
        assert!(matches!(
            Machine::new(vec![repeated], vec![input()], 0, None),
            Err(Error::Order)
        ));
        let huge = FrameSpec {
            scopes: (0..257)
                .map(|scope| Scope {
                    scope,
                    action: scope,
                })
                .collect(),
        };
        assert!(matches!(
            Machine::new(vec![huge], vec![input()], 0, None),
            Err(Error::Budget)
        ));
    }

    #[test]
    fn later_scope_failure_keeps_completed_and_partial_effects_without_retirement() {
        let mut m = machine();
        let first = m.next_cleanup().unwrap().unwrap();
        m.execute_cleanup(first, |view| {
            view.write_trace(9)?;
            view.write_word(0, 42)
        })
        .unwrap();
        assert_eq!(m.frames[2].cursor, 1);
        assert_eq!(m.trace, Some(9));
        let second = m.next_cleanup().unwrap().unwrap();
        assert_eq!(
            m.execute_cleanup(second, |view| {
                assert_eq!(view.read_trace()?, 9);
                assert_eq!(view.read_word(0)?, 42);
                view.write_trace(10)?;
                let _ = view.read_word(4); // Unknown second cell faults mid-scope.
                assert_eq!(view.write_word(0, 99), Err(Error::Uninitialized));
                Ok(())
            }),
            Err(Error::Uninitialized)
        );
        assert_eq!(m.trace, Some(10));
        assert_eq!(m.frames[2].cells, vec![Some(42), None]);
        assert_eq!(m.frames[2].cursor, 1); // Scope B has no completion receipt.
        assert!(m.frames.iter().all(|frame| frame.live));
        assert_eq!(m.restore(0x9000, restore), Err(Error::Phase));
        assert_eq!(
            m.execute_cleanup(second, |_| panic!("failed scope retried")),
            Err(Error::Phase)
        );
        assert_eq!(m.trace, Some(10));
    }

    #[test]
    fn empty_abandoned_frames_retire_after_inner_cleanup_and_stale_requests_cannot_reenter() {
        let specs = vec![
            FrameSpec {
                scopes: vec![Scope {
                    scope: 7,
                    action: 1,
                }],
            },
            FrameSpec { scopes: vec![] },
            FrameSpec {
                scopes: vec![Scope {
                    scope: 8,
                    action: 2,
                }],
            },
        ];
        let inputs = (0..3)
            .map(|i| FrameInput {
                cells: vec![Some(i)],
                context: [0; 10],
            })
            .collect();
        let mut m = Machine::new(specs, inputs, 0, Some(0)).unwrap();
        assert!(m.frames.iter().all(|frame| frame.live));
        let abandoned = m.next_cleanup().unwrap().unwrap();
        m.execute_cleanup(abandoned, |view| view.write_trace(12))
            .unwrap();
        assert!(m.frames[0].live);
        assert!(!m.frames[1].live);
        assert!(!m.frames[2].live);
        let selected = m.next_cleanup().unwrap().unwrap();
        assert_eq!(selected.scope, 7);
        assert_eq!(selected.frame, m.frames[0].id);
        assert_eq!(m.frames[0].cursor, 0);
        assert_eq!(
            m.execute_cleanup(abandoned, |_| panic!("retired frame reentered")),
            Err(Error::Identity)
        );
        assert_eq!(m.frames[0].cursor, 0);
        assert_eq!(m.frames[0].cells, vec![Some(0)]);
        assert_eq!(m.trace, Some(12));
        assert_eq!(m.restore(0, restore), Err(Error::Phase));
    }
}

#[cfg(test)]
mod owned_tests {
    use super::*;

    struct Image {
        binding: OwnedFrameBinding,
        value: u32,
    }
    fn setup() -> (Machine, Vec<Image>) {
        let machine = Machine::new_owned(
            vec![
                FrameSpec { scopes: vec![] },
                FrameSpec {
                    scopes: vec![Scope {
                        scope: 7,
                        action: 3,
                    }],
                },
                FrameSpec {
                    scopes: vec![
                        Scope {
                            scope: 1,
                            action: 1,
                        },
                        Scope {
                            scope: 0,
                            action: 2,
                        },
                    ],
                },
            ],
            1,
            [10, 11, 12, 13, 14, 15, 16, 17, 18, 0x202],
            Some(0),
        )
        .unwrap();
        let images = (0..3)
            .map(|index| Image {
                binding: machine.binding(index).unwrap(),
                value: 10 * (index as u32 + 1),
            })
            .collect();
        (machine, images)
    }
    fn next(machine: &mut Machine, images: &mut [Image]) {
        let request = machine.next_cleanup().unwrap().unwrap();
        machine
            .execute_owned_cleanup(request, |lease, trace| {
                let image = &mut images[lease.frame_index()];
                lease.bind(image.binding)?;
                let action = lease.action().unwrap();
                lease.perform(|| {
                    image.value += action;
                    Ok(())
                })?;
                let prior = trace.read()?;
                trace.write(prior * 16 + action)
            })
            .unwrap();
    }
    fn projection(value: u32) -> [Option<u32>; 10] {
        [
            Some(value),
            None,
            None,
            Some(13),
            Some(0x8000),
            Some(0x8100),
            Some(16),
            Some(17),
            Some(0x9000),
            None,
        ]
    }

    #[test]
    fn connected_nested_cleanup_uses_single_external_image_and_retains_selected_lifetime() {
        let (mut m, mut images) = setup();
        assert_eq!(m.owner(), images[1].binding.owner());
        assert_eq!(images[1].binding.frame_index(), 1);
        for expected in [(2, 1, 1), (2, 0, 2), (1, 7, 3)] {
            let request = m.next_cleanup().unwrap().unwrap();
            m.execute_owned_cleanup(request, |lease, trace| {
                assert_eq!(
                    (
                        lease.frame_index(),
                        lease.scope().unwrap(),
                        lease.action().unwrap()
                    ),
                    expected
                );
                let image = &mut images[lease.frame_index()];
                assert_eq!(lease.owner(), image.binding.owner());
                lease.bind(image.binding)?;
                lease.perform(|| {
                    image.value += expected.2;
                    Ok(())
                })?;
                let prior = trace.read()?;
                trace.write(prior * 16 + expected.2)
            })
            .unwrap();
            assert!(m.frames[1].live);
            assert_eq!(m.frames[2].live, expected.2 == 1);
        }
        assert_eq!(m.trace, Some(0x123));
        assert_eq!(
            images.iter().map(|image| image.value).collect::<Vec<_>>(),
            [10, 23, 33]
        );
        assert!(m
            .frames
            .iter()
            .all(|frame| frame.cells.is_empty() && frame.context == [0; 10]));
        let result = m
            .restore_owned(0x9000, |lease, current| {
                assert_eq!(lease.frame_index(), 1);
                assert_eq!(lease.scope(), None);
                assert_eq!((current[1], current[2], current[9]), (None, None, None));
                let image = &mut images[lease.frame_index()];
                lease.bind(image.binding)?;
                lease.perform(|| {
                    image.value += 5;
                    Ok(projection(image.value))
                })
            })
            .unwrap();
        assert_eq!(result, projection(28));
        assert_eq!(images[1].value, 28);
        assert!(m.frames[0].live && m.frames[1].live && !m.frames[2].live);
        assert_eq!(
            m.restore_owned(0x9000, |_, _| panic!("restoration replay")),
            Err(Error::Phase)
        );
    }

    #[test]
    fn connected_foreign_missing_and_stale_bindings_cannot_grant_receipts() {
        let (foreign, _) = setup();
        for bad_kind in 0..4 {
            let (mut m, _) = setup();
            let request = m.next_cleanup().unwrap().unwrap();
            let mut binding = match bad_kind {
                0 => foreign.owned_binding(2).unwrap(),
                1 => m.owned_binding(1).unwrap(),
                _ => m.owned_binding(2).unwrap(),
            };
            if bad_kind == 2 {
                binding.frame.generation += 1;
            }
            let result = m.execute_owned_cleanup(request, |lease, trace| {
                if bad_kind != 3 {
                    let _ = lease.bind(binding);
                }
                assert_eq!(trace.write(999), Err(Error::Identity));
                assert_eq!(
                    lease.perform(|| panic!("invalid lease executed")),
                    Err::<(), _>(Error::Identity)
                );
                Ok(())
            });
            assert_eq!(result, Err(Error::Identity));
            assert_eq!(m.trace, Some(0));
            assert_eq!(m.frames[2].cursor, 0);
            assert!(m.frames[2].live);
        }
        let (mut m, mut images) = setup();
        let stale = m.next_cleanup().unwrap().unwrap();
        next(&mut m, &mut images);
        assert_eq!(
            m.execute_owned_cleanup(stale, |_, _| panic!("stale request")),
            Err(Error::Order)
        );
        assert_eq!(images[2].value, 31);
        assert_eq!(m.frames[2].cursor, 1);
        let (mut m, _) = setup();
        let request = m.next_cleanup().unwrap().unwrap();
        assert_eq!(
            m.execute_owned_cleanup(request, |_, _| Ok(())),
            Err(Error::Identity)
        );
    }

    #[test]
    fn connected_fault_preserves_prior_external_writes_and_blocks_later_effects() {
        let (mut m, mut images) = setup();
        next(&mut m, &mut images);
        let request = m.next_cleanup().unwrap().unwrap();
        assert_eq!(
            m.execute_owned_cleanup(request, |lease, trace| {
                let image = &mut images[lease.frame_index()];
                lease.bind(image.binding)?;
                trace.write(0x12)?;
                let failure: Result<(), Error> = lease.perform(|| {
                    image.value = 77;
                    Err(Error::Uninitialized)
                });
                assert_eq!(failure, Err(Error::Uninitialized));
                assert_eq!(trace.write(999), Err(Error::Uninitialized));
                assert_eq!(
                    lease.perform(|| {
                        image.value = 999;
                        Ok(())
                    }),
                    Err(Error::Uninitialized)
                );
                Ok(())
            }),
            Err(Error::Uninitialized)
        );
        assert_eq!(images[2].value, 77);
        assert_eq!(m.trace, Some(0x12));
        assert_eq!(m.frames[2].cursor, 1);
        assert!(m.frames[2].live);
        assert_eq!(
            m.restore_owned(0x9000, |_, _| panic!("failed cleanup restored")),
            Err(Error::Phase)
        );
        assert_eq!(
            m.execute_owned_cleanup(request, |_, _| panic!("failed cleanup retried")),
            Err(Error::Phase)
        );
    }

    #[test]
    fn connected_restore_rejects_unknown_promotions_and_retains_failed_landing_writes() {
        for corruption in 0..7 {
            let (mut m, mut images) = setup();
            for _ in 0..3 {
                next(&mut m, &mut images);
            }
            let result = m.restore_owned(0x9000, |lease, _| {
                let image = &mut images[lease.frame_index()];
                lease.bind_storage(image.binding)?;
                let mut out = lease.perform(|| {
                    image.value += 1;
                    Ok(projection(image.value))
                })?;
                match corruption {
                    0 => out[0] = None,
                    1 => out[4] = None,
                    2 => out[8] = Some(0x9001),
                    3 => out[1] = Some(0),
                    4 => out[9] = Some(0x202),
                    5 => out[3] = Some(99),
                    _ => {
                        let _ = lease.perform(|| Err::<(), _>(Error::Cleanup));
                    }
                }
                Ok(out)
            });
            assert_eq!(
                result,
                Err(if corruption == 6 {
                    Error::Cleanup
                } else {
                    Error::Restoration
                })
            );
            assert_eq!(images[1].value, 24);
            assert!(m.frames[1].live);
            assert_eq!(m.phase, Phase::Blocked);
        }
        let (mut m, mut images) = setup();
        for _ in 0..3 {
            next(&mut m, &mut images);
        }
        let out = m
            .restore_owned(0x9000, |lease, _| {
                lease.bind(images[1].binding)?;
                let mut out = projection(7);
                for index in [3, 6, 7] {
                    out[index] = None;
                }
                Ok(out)
            })
            .unwrap();
        assert_eq!((out[3], out[6], out[7]), (None, None, None));
    }

    #[test]
    fn legacy_and_connected_modes_cannot_mix_storage_authority() {
        let (mut m, _) = setup();
        let request = m.next_cleanup().unwrap().unwrap();
        assert_eq!(
            m.execute_cleanup(request, |_| panic!("legacy copy used")),
            Err(Error::Identity)
        );
        let (mut m, _) = setup();
        assert_eq!(
            m.restore(0, |_, _| panic!("legacy context used")),
            Err(Error::Identity)
        );
        let mut legacy = Machine::new(
            vec![FrameSpec {
                scopes: vec![Scope {
                    scope: 0,
                    action: 0,
                }],
            }],
            vec![FrameInput {
                cells: vec![Some(1)],
                context: [0; 10],
            }],
            0,
            Some(0),
        )
        .unwrap();
        assert!(legacy.owned_binding(0).is_err());
        let request = legacy.next_cleanup().unwrap().unwrap();
        assert_eq!(
            legacy.execute_owned_cleanup(request, |_, _| panic!("legacy cells rebound")),
            Err(Error::Identity)
        );
    }
}
