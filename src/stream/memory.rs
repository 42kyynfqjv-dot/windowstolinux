//! Checked, byte-initialized owned storage. No guest address or PE admission authority.
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT_ARENA: AtomicU64 = AtomicU64::new(1);

pub const STORAGE: usize = 4096;
const OBJECTS: usize = 32;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bounds,
    Uninitialized,
    Protected,
    Alias,
    Stale,
    Capacity,
    BackendCount,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pointer {
    arena: u64,
    id: u64,
    offset: usize,
}
impl Pointer {
    pub fn offset(self, n: usize) -> Result<Self, Error> {
        Ok(Self {
            arena: self.arena,
            id: self.id,
            offset: self.offset.checked_add(n).ok_or(Error::Bounds)?,
        })
    }
}
#[derive(Clone, Copy)]
struct Object {
    id: u64,
    start: usize,
    size: usize,
    protected: bool,
}
pub struct Memory {
    arena: u64,
    bytes: [u8; STORAGE],
    initialized: [bool; STORAGE],
    objects: [Option<Object>; OBJECTS],
    next_id: u64,
}
impl Memory {
    pub fn new() -> Result<Self, Error> {
        let mut arena = NEXT_ARENA.load(Ordering::Relaxed);
        loop {
            let next = arena.checked_add(1).ok_or(Error::Capacity)?;
            match NEXT_ARENA.compare_exchange_weak(
                arena,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => arena = current,
            }
        }
        Ok(Self {
            arena,
            bytes: [0; STORAGE],
            initialized: [false; STORAGE],
            objects: [None; OBJECTS],
            next_id: 1,
        })
    }
}
impl Memory {
    pub fn allocate(&mut self, size: usize, protected: bool) -> Result<Pointer, Error> {
        if size == 0 || size > STORAGE {
            return Err(Error::Capacity);
        }
        let slot = self
            .objects
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        // Four-byte alignment keeps external count cells aligned. Object identity,
        // not a sampled numeric address, controls all access and reuse.
        let start = (0..=STORAGE - size)
            .step_by(4)
            .find(|&s| {
                self.objects
                    .iter()
                    .flatten()
                    .all(|o| s + size <= o.start || o.start + o.size <= s)
            })
            .ok_or(Error::Capacity)?;
        let id = self.next_id;
        let next = id.checked_add(1).ok_or(Error::Capacity)?;
        self.initialized[start..start + size].fill(false);
        self.objects[slot] = Some(Object {
            id,
            start,
            size,
            protected,
        });
        self.next_id = next;
        Ok(Pointer {
            arena: self.arena,
            id,
            offset: 0,
        })
    }
    pub fn release(&mut self, p: Pointer) -> Result<(), Error> {
        if p.arena != self.arena {
            return Err(Error::Stale);
        }
        if p.offset != 0 {
            return Err(Error::Bounds);
        }
        let slot = self
            .objects
            .iter()
            .position(|o| o.is_some_and(|o| o.id == p.id))
            .ok_or(Error::Stale)?;
        let o = self.objects[slot].ok_or(Error::Stale)?;
        self.initialized[o.start..o.start + o.size].fill(false);
        self.objects[slot] = None;
        Ok(())
    }
    fn span(&self, p: Pointer, size: usize) -> Result<Range<usize>, Error> {
        if p.arena != self.arena {
            return Err(Error::Stale);
        }
        let o = self
            .objects
            .iter()
            .flatten()
            .find(|o| o.id == p.id)
            .ok_or(Error::Stale)?;
        if o.protected {
            return Err(Error::Protected);
        }
        let end = p.offset.checked_add(size).ok_or(Error::Bounds)?;
        if end > o.size {
            return Err(Error::Bounds);
        }
        Ok(o.start + p.offset..o.start + end)
    }
    pub fn invalidate(&mut self, p: Pointer, size: usize) -> Result<(), Error> {
        let r = self.span(p, size)?;
        self.initialized[r].fill(false);
        Ok(())
    }
    pub fn read(&self, p: Pointer, size: usize) -> Result<&[u8], Error> {
        let r = self.span(p, size)?;
        if !self.initialized[r.clone()].iter().all(|&b| b) {
            return Err(Error::Uninitialized);
        }
        Ok(&self.bytes[r])
    }
    pub fn write(&mut self, p: Pointer, bytes: &[u8]) -> Result<(), Error> {
        let r = self.span(p, bytes.len())?;
        self.bytes[r.clone()].copy_from_slice(bytes);
        self.initialized[r].fill(true);
        Ok(())
    }
    pub fn word(&self, p: Pointer) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(
            self.read(p, 4)?.try_into().map_err(|_| Error::Bounds)?,
        ))
    }
    pub fn put_word(&mut self, p: Pointer, value: u32) -> Result<(), Error> {
        self.write(p, &value.to_le_bytes())
    }
    pub fn pair(&self, buffer: Pointer, size: usize, count: Pointer) -> Result<(), Error> {
        let b = self.span(buffer, size)?;
        let c = self.span(count, 4)?;
        if !c.start.is_multiple_of(4) {
            return Err(Error::Bounds);
        }
        if b.start < c.end && c.start < b.end {
            return Err(Error::Alias);
        }
        Ok(())
    }
    /// External read may alter any requested byte even on failure. Invalidate first;
    /// mark only the reported successful prefix initialized after the call returns.
    pub fn receive<F>(&mut self, p: Pointer, size: usize, f: F) -> Result<Result<usize, u32>, Error>
    where
        F: FnOnce(&mut [u8]) -> Result<usize, u32>,
    {
        let r = self.span(p, size)?;
        self.initialized[r.clone()].fill(false);
        match f(&mut self.bytes[r.clone()]) {
            Ok(n) if n <= size => {
                self.initialized[r.start..r.start + n].fill(true);
                Ok(Ok(n))
            }
            Ok(_) => Err(Error::BackendCount),
            Err(e) => Ok(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn foreign_arena_pointer_never_aliases_matching_allocation_number() {
        let mut a = Memory::new().unwrap();
        let mut b = Memory::new().unwrap();
        let p = a.allocate(4, false).unwrap();
        let q = b.allocate(4, false).unwrap();
        a.put_word(p, 7).unwrap();
        b.put_word(q, 9).unwrap();
        assert_eq!(b.word(p), Err(Error::Stale));
        assert_eq!(a.write(q, &[0]), Err(Error::Stale));
        assert_eq!(b.release(p), Err(Error::Stale));
        assert_eq!(b.word(q), Ok(9));
    }
    #[test]
    fn byte_word_alias_and_unknown_tail() {
        let mut m = Memory::new().unwrap();
        let p = m.allocate(8, false).unwrap();
        m.write(p, &[0x12, 0x34, 0x56]).unwrap();
        assert_eq!(m.word(p), Err(Error::Uninitialized));
        m.write(p.offset(3).unwrap(), &[0x78]).unwrap();
        assert_eq!(m.word(p), Ok(0x78563412));
        m.write(p.offset(1).unwrap(), &[0xab]).unwrap();
        assert_eq!(m.word(p), Ok(0x7856ab12));
        assert_eq!(m.word(p.offset(4).unwrap()), Err(Error::Uninitialized));
    }
    #[test]
    fn ownership_reuse_protection_complete_bounds_and_aliases() {
        let mut m = Memory::new().unwrap();
        let p = m.allocate(8, false).unwrap();
        let q = m.allocate(4, true).unwrap();
        assert_eq!(m.write(q, &[1]), Err(Error::Protected));
        assert_eq!(m.write(p.offset(7).unwrap(), &[1, 2]), Err(Error::Bounds));
        assert_eq!(m.read(p.offset(usize::MAX).unwrap(), 2), Err(Error::Bounds));
        assert_eq!(m.pair(p, 8, p.offset(4).unwrap()), Err(Error::Alias));
        assert_eq!(m.pair(p, 1, p.offset(1).unwrap()), Err(Error::Bounds));
        m.release(p).unwrap();
        let fresh = m.allocate(8, false).unwrap();
        assert_ne!(p, fresh);
        assert_eq!(m.write(p, &[1]), Err(Error::Stale));
        assert_eq!(m.word(fresh), Err(Error::Uninitialized));
    }
    #[test]
    fn external_failure_and_short_success_never_initialize_unknown_bytes() {
        let mut m = Memory::new().unwrap();
        let p = m.allocate(8, false).unwrap();
        m.write(p, &[9; 8]).unwrap();
        assert_eq!(
            m.receive(p, 8, |b| {
                b[0] = 7;
                Err(5)
            }),
            Ok(Err(5))
        );
        assert_eq!(m.read(p, 1), Err(Error::Uninitialized));
        assert_eq!(
            m.receive(p, 8, |b| {
                b[..2].copy_from_slice(&[3, 4]);
                Ok(2)
            }),
            Ok(Ok(2))
        );
        assert_eq!(m.read(p, 2), Ok(&[3, 4][..]));
        assert_eq!(m.read(p, 3), Err(Error::Uninitialized));
        assert_eq!(m.receive(p, 8, |_| Ok(9)), Err(Error::BackendCount));
        assert_eq!(m.read(p, 1), Err(Error::Uninitialized));
    }
    #[test]
    fn allocation_caps_and_one_past_zero_length() {
        let mut m = Memory::new().unwrap();
        let p = m.allocate(STORAGE, false).unwrap();
        assert_eq!(m.allocate(1, false), Err(Error::Capacity));
        assert_eq!(m.read(p.offset(STORAGE).unwrap(), 0), Ok(&[][..]));
        assert_eq!(
            m.read(p.offset(STORAGE + 1).unwrap(), 0),
            Err(Error::Bounds)
        );
        assert_eq!(m.release(p.offset(1).unwrap()), Err(Error::Bounds));
    }
}
