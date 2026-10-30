//! Checked storage for PE32 numeric addresses; no loader/API admission authority.
//! Original implementation: MIT OR Apache-2.0. See research/process/IMPLEMENTATION.md.
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_PROCESS: AtomicU64 = AtomicU64::new(1);
pub const MAX_BYTES: usize = 1024 * 1024;
pub const MAX_REGIONS: usize = 64;
pub const PAGE_SIZE: u32 = 4096;

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
    pub const NONE: Self = Self {
        read: false,
        write: false,
        execute: false,
    };
    pub fn windows_data(self) -> Result<u32, Fault> {
        match self {
            Self::NONE => Ok(1),
            Self::READ => Ok(2),
            Self::READ_WRITE => Ok(4),
            _ => Err(Fault::Permission),
        }
    }
    pub fn from_windows_data(value: u32) -> Result<Self, Fault> {
        match value {
            1 => Ok(Self::NONE),
            2 => Ok(Self::READ),
            4 => Ok(Self::READ_WRITE),
            _ => Err(Fault::Permission),
        }
    }
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
    pages: Vec<Permissions>,
    protected_pages: bool,
    bytes: Vec<u8>,
    defined: Vec<bool>,
    epoch: u64,
    heap_allocation: bool,
}
impl Region {
    fn reserved_end(&self) -> u64 {
        let end = u64::from(self.capability.base) + self.bytes.len() as u64;
        if self.protected_pages {
            end.div_ceil(u64::from(PAGE_SIZE)) * u64::from(PAGE_SIZE)
        } else {
            end
        }
    }
    fn page_range(&self, address: u32, size: u32) -> std::ops::Range<usize> {
        let first = self.capability.base / PAGE_SIZE;
        let last = (u64::from(address) + u64::from(size) - 1) / u64::from(PAGE_SIZE);
        (address / PAGE_SIZE - first) as usize..(last - u64::from(first) + 1) as usize
    }
    fn permits(&self, address: u32, size: u32, test: impl Fn(Permissions) -> bool) -> bool {
        self.pages[self.page_range(address, size)]
            .iter()
            .copied()
            .all(test)
    }
}
fn page_permissions(
    base: u32,
    size: u32,
    permission: Permissions,
) -> Result<Vec<Permissions>, Fault> {
    end(base, size)?;
    let count =
        ((u64::from(base % PAGE_SIZE) + u64::from(size)).div_ceil(u64::from(PAGE_SIZE))) as usize;
    let mut pages = Vec::new();
    pages.try_reserve_exact(count).map_err(|_| Fault::Budget)?;
    pages.resize(count, permission);
    Ok(pages)
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
        if self
            .regions
            .iter()
            .any(|r| u64::from(base) < r.reserved_end() && u64::from(r.capability.base) < limit)
        {
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
        let pages = page_permissions(base, size, permissions)?;
        self.regions.push(Region {
            capability,
            permissions,
            pages,
            protected_pages: false,
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
    /// Bounded preferred-base PE32 storage mapping, not loader execution or API
    /// admission. Headers and disjoint sections retain separate capabilities.
    /// Unsupported alignments/permissions reject; gaps remain unmapped. A failed
    /// transaction removes only its own regions, never pre-existing mappings.
    /// Discardable sections are initial storage only: this grants no claim that
    /// a Windows loader retained them after initialization. No discard is modeled.
    pub fn map_pe32(
        &mut self,
        module: u64,
        file: &[u8],
    ) -> Result<Vec<(Capability, u32, u32)>, Fault> {
        let get = |at: usize, n: usize| {
            file.get(at..at.checked_add(n).ok_or(Fault::Range)?)
                .ok_or(Fault::Range)
        };
        let word =
            |at| -> Result<u16, Fault> { Ok(u16::from_le_bytes(get(at, 2)?.try_into().unwrap())) };
        let dword =
            |at| -> Result<u32, Fault> { Ok(u32::from_le_bytes(get(at, 4)?.try_into().unwrap())) };
        if file.len() > 4 * MAX_BYTES || get(0, 2)? != b"MZ" {
            return Err(Fault::Range);
        }
        let pe = dword(0x3c)? as usize;
        // The bounded file check prevents offset arithmetic overflow on all hosts.
        get(pe, 24)?;
        if get(pe, 4)? != b"PE\0\0" || word(pe + 4)? != 0x14c {
            return Err(Fault::Range);
        }
        let count = word(pe + 6)? as usize;
        let flags = word(pe + 22)?;
        let opt = pe + 24;
        if !(1..=16).contains(&count) || word(pe + 20)? != 224 || flags & 0x2002 != 2 {
            return Err(Fault::Range);
        }
        get(opt, 224)?;
        if word(opt)? != 0x10b
            || !matches!(word(opt + 68)?, 2 | 3)
            || dword(opt + 32)? != 4096
            || dword(opt + 36)? != 512
        {
            return Err(Fault::Range);
        }
        let base = dword(opt + 28)?;
        let size = dword(opt + 56)?;
        let headers = dword(opt + 60)?;
        if base == 0
            || !base.is_multiple_of(65536)
            || size == 0
            || !size.is_multiple_of(4096)
            || size as usize > MAX_BYTES
            || base.checked_add(size).is_none()
            || headers == 0
            || !headers.is_multiple_of(512)
            || headers > 4096
            || headers > size
            || (headers as usize) < opt + 224 + count * 40
        {
            return Err(Fault::Range);
        }
        get(0, headers as usize)?;
        let mut plan = vec![(base, headers, Permissions::READ, 0usize, headers as usize)];
        let mut raw_ranges = Vec::new();
        let mut entry = false;
        for i in 0..count {
            let at = opt + 224 + i * 40;
            get(at, 40)?;
            let vs = dword(at + 8)?;
            let rva = dword(at + 12)?;
            let raw = dword(at + 16)?;
            let offset = dword(at + 20)?;
            let ch = dword(at + 36)?;
            let permissions = match ch & 0xe0000000 {
                0x40000000 => Permissions::READ,
                0x60000000 => Permissions::READ_EXECUTE,
                0xc0000000 => Permissions::READ_WRITE,
                _ => return Err(Fault::Permission),
            };
            // Reject shared/not-cached/not-paged and COFF relocation
            // metadata. Ordinary code/data content flags do not grant effects.
            if ch & 0x1dffff1f != 0
                || dword(at + 24)? != 0
                || dword(at + 28)? != 0
                || dword(at + 32)? != 0
            {
                return Err(Fault::Permission);
            }
            let extent = vs.max(raw);
            let limit = rva.checked_add(extent).ok_or(Fault::Range)?;
            if vs == 0
                || rva < 4096
                || !rva.is_multiple_of(4096)
                || extent == 0
                || limit > size
                || !raw.is_multiple_of(512)
                || (raw != 0 && (offset < headers || !offset.is_multiple_of(512)))
            {
                return Err(Fault::Range);
            }
            let source = if raw == 0 {
                &file[0..0]
            } else {
                get(offset as usize, raw as usize)?
            };
            if raw != 0 {
                let end = offset.checked_add(raw).ok_or(Fault::Range)?;
                if raw_ranges.iter().any(|&(a, b)| offset < b && a < end) {
                    return Err(Fault::Overlap);
                }
                raw_ranges.push((offset, end));
            }
            let address = base.checked_add(rva).ok_or(Fault::Range)?;
            // Distinct sections may not share a page, even if byte ranges don't overlap.
            let page_end = limit.checked_add(4095).ok_or(Fault::Range)? & !4095;
            for &(old, len, _, _, _) in plan.iter().skip(1) {
                let old_rva = old - base;
                let old_end = (old_rva + len + 4095) & !4095;
                if rva < old_end && old_rva < page_end {
                    return Err(Fault::Overlap);
                }
            }
            let ep = dword(opt + 16)?;
            if ep >= rva && ep < limit && permissions.execute {
                entry = true;
            }
            plan.push((
                address,
                extent,
                permissions,
                if raw == 0 { 0 } else { offset as usize },
                source.len(),
            ));
        }
        if !entry {
            return Err(Fault::Permission);
        }
        let mut mapped = Vec::with_capacity(plan.len());
        for (address, size, permissions, offset, len) in plan {
            match self.map_image(
                address,
                size,
                module,
                permissions,
                &file[offset..offset + len],
            ) {
                Ok(cap) => mapped.push((cap, address, size)),
                Err(fault) => {
                    for &(cap, _, _) in &mapped {
                        self.release(cap, Owner::Module(module))?;
                    }
                    return Err(fault);
                }
            }
        }
        Ok(mapped)
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
    /// Check writable ownership without defining bytes or changing read epochs.
    pub fn validate_writable(
        &self,
        cap: Capability,
        owner: Owner,
        address: u32,
        size: u32,
    ) -> Result<(), Fault> {
        self.validate_range(cap, owner, address, size)?;
        let (i, _) = self.locate(address, size)?;
        if !self.regions[i].permits(address, size, |p| p.write) {
            return Err(Fault::Permission);
        }
        Ok(())
    }
    /// Read permission without asserting initialization, including typed loads.
    pub fn validate_readable(
        &self,
        cap: Capability,
        owner: Owner,
        address: u32,
        size: u32,
    ) -> Result<(), Fault> {
        self.validate_range(cap, owner, address, size)?;
        let (i, _) = self.locate(address, size)?;
        if !self.regions[i].permits(address, size, |p| p.read) {
            return Err(Fault::Permission);
        }
        Ok(())
    }
    /// Bounded VirtualProtect storage transaction. One page-aligned module region,
    /// data protections only; no executable transitions or heap-page inference.
    /// The last mapped page may be partial: its protection changes, but its absent
    /// bytes remain inaccessible. Separate section/reservation spans reject.
    /// Output must be disjoint from every affected page. All validation and epoch
    /// reservation precedes the permission change AND output write; no allocation
    /// or fallible operation remains after the commit point. Errors are rejection
    /// of this subset, not fabricated Windows BOOL/LastError observations.
    pub fn protect_data_with_old(
        &mut self,
        target: (Capability, Owner, u32, u32),
        protection: u32,
        output: (Capability, Owner, u32),
    ) -> Result<(), Fault> {
        let (target, owner, address, size) = target;
        let (output, output_owner, old_address) = output;
        let new = Permissions::from_windows_data(protection)?;
        self.validate_range(target, owner, address, size)?;
        let i = self.token(target, owner)?;
        if !matches!(owner, Owner::Module(_)) || !target.base.is_multiple_of(PAGE_SIZE) {
            return Err(Fault::Permission);
        }
        let pages = self.regions[i].page_range(address, size);
        let page_begin = u64::from(address / PAGE_SIZE * PAGE_SIZE);
        let page_end =
            (end(address, size)? + u64::from(PAGE_SIZE) - 1) & !(u64::from(PAGE_SIZE) - 1);
        // Reject another region sharing any affected page, even if logical bytes
        // do not overlap. A capability is not authority over its neighbors.
        if self.regions.iter().enumerate().any(|(j, r)| {
            j != i && u64::from(r.capability.base) < page_end && page_begin < r.reserved_end()
        }) {
            return Err(Fault::Overlap);
        }
        if self.regions[i].pages[pages.clone()]
            .iter()
            .any(|p| p.execute)
        {
            return Err(Fault::Permission);
        }
        self.validate_writable(output, output_owner, old_address, 4)?;
        let (j, destination) = self.locate(old_address, 4)?;
        if u64::from(old_address) < page_end && page_begin < end(old_address, 4)? {
            return Err(Fault::Overlap);
        }
        let old = self.regions[i].pages[pages.start].windows_data()?;
        let target_epoch = self.regions[i].epoch.checked_add(1).ok_or(Fault::Budget)?;
        let output_epoch = self.regions[j]
            .epoch
            .checked_add(if i == j { 2 } else { 1 })
            .ok_or(Fault::Budget)?;
        self.regions[i].pages[pages].fill(new);
        self.regions[i].protected_pages = true;
        self.regions[i].epoch = target_epoch;
        self.regions[j].bytes[destination.clone()].copy_from_slice(&old.to_le_bytes());
        self.regions[j].defined[destination].fill(true);
        self.regions[j].epoch = output_epoch;
        Ok(())
    }
    /// Every page in a snapshot's range must remain non-writable.
    pub fn validate_immutable(
        &self,
        cap: Capability,
        owner: Owner,
        address: u32,
        size: u32,
    ) -> Result<(), Fault> {
        self.validate_range(cap, owner, address, size)?;
        let (i, _) = self.locate(address, size)?;
        if !self.regions[i].permits(address, size, |p| !p.write) {
            return Err(Fault::Permission);
        }
        Ok(())
    }
    /// Validate code ownership and execute permission without granting access
    /// to a different mapping or converting a readable data page into code.
    pub fn validate_executable(
        &self,
        cap: Capability,
        owner: Owner,
        address: u32,
        size: u32,
    ) -> Result<(), Fault> {
        self.validate_range(cap, owner, address, size)?;
        let (i, _) = self.locate(address, size)?;
        if !self.regions[i].permits(address, size, |p| p.execute) {
            return Err(Fault::Permission);
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
        if !r.permits(address, size, |p| p.read) {
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
        if !r.permits(address, size, |p| p.write) {
            return Err(Fault::Permission);
        }
        r.epoch = r.epoch.checked_add(1).ok_or(Fault::Budget)?;
        Ok(&mut r.bytes[s])
    }
    /// Trusted effect postcondition only. This cannot grant permissions or enlarge a region.
    pub fn define(&mut self, address: u32, size: u32) -> Result<(), Fault> {
        let (i, s) = self.locate(address, size)?;
        let r = &mut self.regions[i];
        if !r.permits(address, size, |p| p.write) {
            return Err(Fault::Permission);
        }
        r.epoch = r.epoch.checked_add(1).ok_or(Fault::Budget)?;
        r.defined[s].fill(true);
        Ok(())
    }
    pub fn forget(&mut self, address: u32, size: u32) -> Result<(), Fault> {
        let (i, s) = self.locate(address, size)?;
        let r = &mut self.regions[i];
        if !r.permits(address, size, |p| p.write) {
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
                .filter(|(_, r)| base < r.reserved_end() && u64::from(r.capability.base) < limit)
                .map(|(_, r)| r.reserved_end())
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
                    && u64::from(address) < r.reserved_end()
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
        let pages = page_permissions(base, size, Permissions::READ_WRITE)?;
        self.regions[i] = Region {
            capability,
            permissions: Permissions::READ_WRITE,
            pages,
            protected_pages: false,
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
