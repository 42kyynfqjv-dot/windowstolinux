//! Checked storage for PE32 numeric addresses; no loader/API admission authority.
//! Original implementation: MIT OR Apache-2.0. See research/process/IMPLEMENTATION.md.
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_PROCESS: AtomicU64 = AtomicU64::new(1);
pub const MAX_BYTES: usize = 1024 * 1024;
pub const MAX_REGIONS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Range,
    Overlap,
    Permission,
    Uninitialized,
    Identity,
    Stale,
    Budget,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    Module(u64),
    Heap(u64),
    Stack(u64),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissions {
    read: bool,
    write: bool,
    execute: bool,
}
impl Permissions {
    pub const READ: Self = Self {
        read: true,
        write: false,
        execute: false,
    };
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
    pub const READ_EXECUTE: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
}
/// Opaque proof identity, never stored in a guest register in place of address bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capability {
    process: u64,
    base: u32,
    generation: u64,
    owner: Owner,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadFact {
    capability: Capability,
    address: u32,
    size: u32,
    epoch: u64,
}
struct Region {
    capability: Capability,
    permissions: Permissions,
    bytes: Vec<u8>,
    defined: Vec<bool>,
    epoch: u64,
    heap_allocation: bool,
}
/// Not Clone: independent spaces must never share a proof identity.
pub struct Space {
    identity: u64,
    generation: u64,
    regions: Vec<Region>,
    bytes: usize,
    byte_limit: usize,
    region_limit: usize,
}

fn end(address: u32, size: u32) -> Result<u64, Fault> {
    let end = u64::from(address) + u64::from(size);
    if address == 0 || size == 0 || end > (1u64 << 32) {
        return Err(Fault::Range);
    }
    Ok(end)
}
impl Space {
    pub fn new(byte_limit: usize, region_limit: usize) -> Result<Self, Fault> {
        if byte_limit == 0
            || byte_limit > MAX_BYTES
            || region_limit == 0
            || region_limit > MAX_REGIONS
        {
            return Err(Fault::Budget);
        }
        let mut identity = NEXT_PROCESS.load(Ordering::Relaxed);
        loop {
            let next = identity.checked_add(1).ok_or(Fault::Budget)?;
            match NEXT_PROCESS.compare_exchange_weak(
                identity,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => identity = actual,
            }
        }
        Ok(Self {
            identity,
            generation: 0,
            regions: Vec::new(),
            bytes: 0,
            byte_limit,
            region_limit,
        })
    }
    /// Map a disjoint region. Defined zero-fill is distinct from unknown backing.
    /// Initialized image bytes can subsequently be provided with map_image.
    pub fn map(
        &mut self,
        base: u32,
        size: u32,
        owner: Owner,
        permissions: Permissions,
        zeroed: bool,
    ) -> Result<Capability, Fault> {
        let limit = end(base, size)?;
        if permissions.write && permissions.execute {
            return Err(Fault::Permission);
        }
        if self.regions.iter().any(|r| {
            u64::from(base) < u64::from(r.capability.base) + r.bytes.len() as u64
                && u64::from(r.capability.base) < limit
        }) {
            return Err(Fault::Overlap);
        }
        let total = self.bytes.checked_add(size as usize).ok_or(Fault::Budget)?;
        if total > self.byte_limit || self.regions.len() >= self.region_limit {
            return Err(Fault::Budget);
        }
        let generation = self.generation.checked_add(1).ok_or(Fault::Budget)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size as usize)
            .map_err(|_| Fault::Budget)?;
        bytes.resize(size as usize, 0);
        let mut defined = Vec::new();
        defined
            .try_reserve_exact(size as usize)
            .map_err(|_| Fault::Budget)?;
        defined.resize(size as usize, zeroed);
        self.regions.try_reserve(1).map_err(|_| Fault::Budget)?;
        let capability = Capability {
            process: self.identity,
            base,
            generation,
            owner,
        };
        self.regions.push(Region {
            capability,
            permissions,
            bytes,
            defined,
            epoch: 0,
            heap_allocation: false,
        });
        self.generation = generation;
        self.bytes = total;
        Ok(capability)
    }
    /// Loader-specified bytes and zero tail; callers must separately prove PE layout.
    pub fn map_image(
        &mut self,
        base: u32,
        size: u32,
        module: u64,
        permissions: Permissions,
        image: &[u8],
    ) -> Result<Capability, Fault> {
        if image.len() > size as usize {
            return Err(Fault::Range);
        }
        let cap = self.map(base, size, Owner::Module(module), permissions, true)?;
        let r = self.regions.last_mut().unwrap();
        r.bytes[..image.len()].copy_from_slice(image);
        Ok(cap)
    }
    fn locate(&self, address: u32, size: u32) -> Result<(usize, std::ops::Range<usize>), Fault> {
        let limit = end(address, size)?;
        for (i, r) in self.regions.iter().enumerate() {
            let base = r.capability.base;
            if address >= base && limit <= u64::from(base) + r.bytes.len() as u64 {
                let offset = (address - base) as usize;
                return Ok((i, offset..offset + size as usize));
            }
        }
        Err(Fault::Range)
    }
    fn token(&self, cap: Capability, owner: Owner) -> Result<usize, Fault> {
        if cap.process != self.identity || cap.owner != owner {
            return Err(Fault::Identity);
        }
        self.regions
            .iter()
            .position(|r| r.capability == cap)
            .ok_or(Fault::Stale)
    }
    pub fn validate(&self, cap: Capability, owner: Owner) -> Result<(), Fault> {
        self.token(cap, owner).map(|_| ())
    }
    /// Check identity and complete range without claiming bytes initialized or
    /// granting access permissions. Used before formation of owned destinations.
    pub fn validate_range(
        &self,
        cap: Capability,
        owner: Owner,
        address: u32,
        size: u32,
    ) -> Result<(), Fault> {
        let i = self.token(cap, owner)?;
        let (j, _) = self.locate(address, size)?;
        if i != j {
            return Err(Fault::Identity);
        }
        Ok(())
    }
    pub fn release(&mut self, cap: Capability, owner: Owner) -> Result<(), Fault> {
        let i = self.token(cap, owner)?;
        self.bytes -= self.regions.remove(i).bytes.len();
        Ok(())
    }
    pub fn read(&self, address: u32, size: u32) -> Result<&[u8], Fault> {
        let (i, s) = self.locate(address, size)?;
        let r = &self.regions[i];
        if !r.permissions.read {
            return Err(Fault::Permission);
        }
        if !r.defined[s.clone()].iter().all(|&b| b) {
            return Err(Fault::Uninitialized);
        }
        Ok(&r.bytes[s])
    }
    /// Invalidate derived facts before lending writable bytes. This does not make
    /// unknown bytes defined; the effect adapter must commit its promised prefix.
    /// Existing defined bytes remain physically defined, independent of freshness.
    pub fn destination(&mut self, address: u32, size: u32) -> Result<&mut [u8], Fault> {
        let (i, s) = self.locate(address, size)?;
        let r = &mut self.regions[i];
        if !r.permissions.write {
            return Err(Fault::Permission);
        }
        r.epoch = r.epoch.checked_add(1).ok_or(Fault::Budget)?;
        Ok(&mut r.bytes[s])
    }
    /// Trusted effect postcondition only. This cannot grant permissions or enlarge a region.
    pub fn define(&mut self, address: u32, size: u32) -> Result<(), Fault> {
        let (i, s) = self.locate(address, size)?;
        let r = &mut self.regions[i];
        if !r.permissions.write {
            return Err(Fault::Permission);
        }
        r.epoch = r.epoch.checked_add(1).ok_or(Fault::Budget)?;
        r.defined[s].fill(true);
        Ok(())
    }
    pub fn forget(&mut self, address: u32, size: u32) -> Result<(), Fault> {
        let (i, s) = self.locate(address, size)?;
        let r = &mut self.regions[i];
        if !r.permissions.write {
            return Err(Fault::Permission);
        }
        r.epoch = r.epoch.checked_add(1).ok_or(Fault::Budget)?;
        r.defined[s].fill(false);
        Ok(())
    }
    pub fn write(&mut self, address: u32, bytes: &[u8]) -> Result<(), Fault> {
        let size = u32::try_from(bytes.len()).map_err(|_| Fault::Range)?;
        // Reserve both epoch increments before changing any bytes.
        let (i, _) = self.locate(address, size)?;
        self.regions[i].epoch.checked_add(2).ok_or(Fault::Budget)?;
        self.destination(address, size)?.copy_from_slice(bytes);
        self.define(address, size)
    }
    pub fn prove_read(
        &self,
        cap: Capability,
        owner: Owner,
        address: u32,
        size: u32,
    ) -> Result<ReadFact, Fault> {
        let i = self.token(cap, owner)?;
        let (j, _) = self.locate(address, size)?;
        if i != j {
            return Err(Fault::Identity);
        }
        self.read(address, size)?;
        Ok(ReadFact {
            capability: cap,
            address,
            size,
            epoch: self.regions[i].epoch,
        })
    }
    pub fn read_proven(&self, fact: ReadFact, owner: Owner) -> Result<&[u8], Fault> {
        let i = self.token(fact.capability, owner)?;
        if self.regions[i].epoch != fact.epoch {
            return Err(Fault::Stale);
        }
        self.read(fact.address, fact.size)
    }
    /// Selected moving storage transition, NOT a HeapReAlloc implementation.
    /// Failed validation/budget/allocation leaves the old mapping and facts intact.
    pub fn move_resize(
        &mut self,
        cap: Capability,
        owner: Owner,
        base: u32,
        size: u32,
        zero_tail: bool,
    ) -> Result<Capability, Fault> {
        let i = self.token(cap, owner)?;
        if !matches!(owner, Owner::Heap(_)) {
            return Err(Fault::Identity);
        }
        let permissions = self.regions[i].permissions;
        let new = self.map(base, size, owner, permissions, zero_tail)?;
        let j = self.regions.len() - 1;
        let (old, new_region) = self.regions.split_at_mut(j);
        let n = old[i].bytes.len().min(size as usize);
        new_region[0].bytes[..n].copy_from_slice(&old[i].bytes[..n]);
        new_region[0].defined[..n].copy_from_slice(&old[i].defined[..n]);
        self.release(cap, owner)?;
        Ok(new)
    }
}

/// Host-side proof of default-heap identity, not a guest HANDLE encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessHeap {
    process: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeapError {
    UnsupportedFlags,
    UnsupportedSize,
    InvalidPointer,
    Memory(Fault),
}
impl From<Fault> for HeapError {
    fn from(value: Fault) -> Self {
        Self::Memory(value)
    }
}
/// Trusted effect input. Failure is injected conformance evidence, not a claim
/// that native and Windows resource exhaustion occur at the same allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Availability {
    Available,
    AllocationFailed,
}
const HEAP_START: u32 = 0x1000_0000;
const HEAP_END: u64 = 0x2000_0000;
const PROCESS_HEAP_OWNER: Owner = Owner::Heap(0);

impl Space {
    pub fn process_heap(&self) -> ProcessHeap {
        ProcessHeap {
            process: self.identity,
        }
    }
    fn check_heap(&self, heap: ProcessHeap) -> Result<(), HeapError> {
        if heap.process != self.identity {
            return Err(Fault::Identity.into());
        }
        Ok(())
    }
    fn heap_request(&self, heap: ProcessHeap, flags: u32, size: u32) -> Result<(), HeapError> {
        self.check_heap(heap)?;
        if flags & !8 != 0 {
            return Err(HeapError::UnsupportedFlags);
        }
        // Zero-sized blocks and rounding-visible slack are outside this contract.
        if size == 0 {
            return Err(HeapError::UnsupportedSize);
        }
        Ok(())
    }
    fn heap_index(&self, address: u32) -> Result<usize, HeapError> {
        self.regions
            .iter()
            .position(|r| {
                r.capability.base == address
                    && r.capability.owner == PROCESS_HEAP_OWNER
                    && r.heap_allocation
            })
            .ok_or(HeapError::InvalidPointer)
    }
    fn heap_gap(&self, size: u32, exclude: Option<usize>) -> Result<u32, HeapError> {
        // First fit over actual numeric mappings; no host pointers or fixture IDs.
        let mut base = u64::from(HEAP_START);
        loop {
            let limit = base + u64::from(size);
            if limit > HEAP_END {
                return Err(Fault::Budget.into());
            }
            let blocker = self
                .regions
                .iter()
                .enumerate()
                .filter(|(i, _)| Some(*i) != exclude)
                .filter(|(_, r)| {
                    base < u64::from(r.capability.base) + r.bytes.len() as u64
                        && u64::from(r.capability.base) < limit
                })
                .map(|(_, r)| u64::from(r.capability.base) + r.bytes.len() as u64)
                .max();
            match blocker {
                None => return Ok(base as u32),
                Some(next) => base = (next + 7) & !7,
            }
        }
    }
    /// Bounded successful/default-heap effect; None is an explicitly supplied
    /// allocation failure. Host/proof budgets are errors, never fabricated NULL.
    pub fn heap_alloc(
        &mut self,
        heap: ProcessHeap,
        flags: u32,
        size: u32,
        availability: Availability,
    ) -> Result<Option<u32>, HeapError> {
        self.heap_request(heap, flags, size)?;
        if availability == Availability::AllocationFailed {
            return Ok(None);
        }
        let base = self.heap_gap(size, None)?;
        self.map(
            base,
            size,
            PROCESS_HEAP_OWNER,
            Permissions::READ_WRITE,
            flags & 8 != 0,
        )?;
        self.regions.last_mut().unwrap().heap_allocation = true;
        Ok(Some(base))
    }
    pub fn heap_capability(
        &self,
        heap: ProcessHeap,
        address: u32,
    ) -> Result<Capability, HeapError> {
        self.check_heap(heap)?;
        Ok(self.regions[self.heap_index(address)?].capability)
    }
    /// Requested-size bounds only; placement/address-sensitive behavior is not
    /// Windows-equivalent merely because this effect uses numeric PE32 addresses.
    pub fn heap_realloc(
        &mut self,
        heap: ProcessHeap,
        flags: u32,
        address: u32,
        size: u32,
        availability: Availability,
    ) -> Result<Option<u32>, HeapError> {
        self.heap_request(heap, flags, size)?;
        let i = self.heap_index(address)?;
        if availability == Availability::AllocationFailed {
            return Ok(None);
        }
        let total = (self.bytes - self.regions[i].bytes.len())
            .checked_add(size as usize)
            .ok_or(Fault::Budget)?;
        if total > self.byte_limit {
            return Err(Fault::Budget.into());
        }
        let generation = self.generation.checked_add(1).ok_or(Fault::Budget)?;
        let limit = u64::from(address) + u64::from(size);
        let fits = limit <= HEAP_END
            && !self.regions.iter().enumerate().any(|(j, r)| {
                i != j
                    && u64::from(address) < u64::from(r.capability.base) + r.bytes.len() as u64
                    && u64::from(r.capability.base) < limit
            });
        let base = if fits {
            address
        } else {
            self.heap_gap(size, Some(i))?
        };
        // Allocate and populate replacement before committing anything. Peak host
        // storage is bounded by old+new, while the logical budget is final size.
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size as usize)
            .map_err(|_| Fault::Budget)?;
        bytes.resize(size as usize, 0);
        let mut defined = Vec::new();
        defined
            .try_reserve_exact(size as usize)
            .map_err(|_| Fault::Budget)?;
        defined.resize(size as usize, flags & 8 != 0);
        let n = self.regions[i].bytes.len().min(size as usize);
        bytes[..n].copy_from_slice(&self.regions[i].bytes[..n]);
        defined[..n].copy_from_slice(&self.regions[i].defined[..n]);
        let capability = Capability {
            process: self.identity,
            base,
            generation,
            owner: PROCESS_HEAP_OWNER,
        };
        self.regions[i] = Region {
            capability,
            permissions: Permissions::READ_WRITE,
            bytes,
            defined,
            epoch: 0,
            heap_allocation: true,
        };
        self.bytes = total;
        self.generation = generation;
        Ok(Some(base))
    }
    /// Invalid/null/interior pointers reject out of domain, not invented Windows
    /// BOOL/LastError results. Successful frees invalidate facts, not numeric bits.
    pub fn heap_free(
        &mut self,
        heap: ProcessHeap,
        flags: u32,
        address: u32,
    ) -> Result<(), HeapError> {
        self.check_heap(heap)?;
        if flags != 0 {
            return Err(HeapError::UnsupportedFlags);
        }
        let i = self.heap_index(address)?;
        let capability = self.regions[i].capability;
        self.release(capability, PROCESS_HEAP_OWNER)?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "guest_memory_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "guest_heap_tests.rs"]
mod heap_tests;
