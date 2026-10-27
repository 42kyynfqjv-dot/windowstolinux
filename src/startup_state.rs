//! Isolated byte-backed startup state. No decoder/emission admission authority.
//! Original MIT OR Apache-2.0 implementation; see research/process/startup/BYTES.md.
use crate::guest_memory::{Capability, Fault, Owner, Permissions, Space};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Memory(Fault),
    Identity,
    Unknown,
    Corrupt,
    Active,
    Pending,
    Budget,
}
impl From<Fault> for Error {
    fn from(value: Fault) -> Self {
        Self::Memory(value)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Module(Capability);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Thread(Capability);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pointer {
    cap: Capability,
    owner: Owner,
    address: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Encoded {
    target: Pointer,
    module: Module,
    version: u64,
    bits: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value {
    Pointer(Pointer),
    Encoded(Encoded),
    Guard {
        module: Module,
        version: u64,
        frame: Pointer,
    },
}
#[derive(Clone, Copy)]
struct Cell {
    destination: Pointer,
    value: Value,
}
struct Image {
    token: Module,
    owner: Owner,
    code: Capability,
    data: Capability,
    cookie: Capability,
    cookie_address: u32,
    value: Option<u32>,
    version: u64,
}
#[derive(Clone, Copy)]
struct Record {
    pointer: Pointer,
    module: Module,
    scope: Encoded,
    handler: Pointer,
    guard: Pointer,
}
struct ThreadState {
    token: Thread,
    owner: Owner,
    head: u32,
    records: Vec<Record>,
}
/// A validated chain snapshot is a request to a future dispatcher, NOT authority
/// to call an arbitrary guest handler or to resume normal execution.
#[derive(Debug, PartialEq, Eq)]
pub struct Dispatch {
    pub code: u32,
    pub continuable: bool,
    pub handlers: Vec<u32>,
}
/// An observed/documented effect input, not a replacement entropy source.
#[derive(Clone, Copy)]
pub enum EntropyOutput {
    FileTime(u64),
    PerformanceCounter { counter: i64, success: u32 },
}
#[derive(Debug, PartialEq, Eq)]
pub struct CallEffects {
    pub eax: Option<u32>,
    // x86 caller-saved ECX/EDX and flags remain unknown after these calls.
    pub volatile_registers_known: bool,
    pub flags_known: bool,
    pub last_error_known: bool,
}
pub struct Startup {
    memory: Space,
    images: Vec<Image>,
    threads: Vec<ThreadState>,
    cells: Vec<Cell>,
    next_owner: u64,
    pending: bool,
}
fn overlaps(a: u32, n: u32, b: u32, m: u32) -> bool {
    u64::from(a) < u64::from(b) + u64::from(m) && u64::from(b) < u64::from(a) + u64::from(n)
}
impl Startup {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            memory: Space::new(1 << 20, 64)?,
            images: Vec::new(),
            threads: Vec::new(),
            cells: Vec::new(),
            next_owner: 1,
            pending: false,
        })
    }
    fn runnable(&self) -> Result<(), Error> {
        if self.pending {
            Err(Error::Pending)
        } else {
            Ok(())
        }
    }
    fn image(&self, module: Module) -> Result<usize, Error> {
        self.images
            .iter()
            .position(|m| m.token == module)
            .ok_or(Error::Identity)
    }
    fn thread(&self, thread: Thread) -> Result<usize, Error> {
        self.threads
            .iter()
            .position(|t| t.token == thread)
            .ok_or(Error::Identity)
    }
    fn next(&mut self) -> Result<u64, Error> {
        let id = self.next_owner;
        self.next_owner = id.checked_add(1).ok_or(Error::Budget)?;
        Ok(id)
    }
    /// Trusted layout input, not a PE loader. Distinct RX, immutable scope bytes
    /// and an eight-byte mutable cookie/complement pair. Failed maps roll back.
    pub fn map_module(
        &mut self,
        code: (u32, &[u8]),
        data: (u32, &[u8]),
        cookie: u32,
    ) -> Result<Module, Error> {
        self.runnable()?;
        let code_size = u32::try_from(code.1.len()).map_err(|_| Error::Budget)?;
        let data_size = u32::try_from(data.1.len()).map_err(|_| Error::Budget)?;
        let id = self.next()?;
        let owner = Owner::Module(id);
        let code_cap =
            self.memory
                .map_image(code.0, code_size, id, Permissions::READ_EXECUTE, code.1)?;
        let data_cap = match self
            .memory
            .map_image(data.0, data_size, id, Permissions::READ, data.1)
        {
            Ok(cap) => cap,
            Err(e) => {
                self.memory.release(code_cap, owner)?;
                return Err(e.into());
            }
        };
        let cookie_cap = match self
            .memory
            .map(cookie, 8, owner, Permissions::READ_WRITE, false)
        {
            Ok(cap) => cap,
            Err(e) => {
                self.memory.release(data_cap, owner)?;
                self.memory.release(code_cap, owner)?;
                return Err(e.into());
            }
        };
        let token = Module(code_cap);
        self.images.push(Image {
            token,
            owner,
            code: code_cap,
            data: data_cap,
            cookie: cookie_cap,
            cookie_address: cookie,
            value: None,
            version: 0,
        });
        Ok(token)
    }
    /// Explicit empty-chain premise. This is not a claim about an arbitrary
    /// incoming Windows TEB; production must supply a validated initial chain.
    pub fn bind_empty_thread(&mut self, base: u32, size: u32) -> Result<Thread, Error> {
        self.runnable()?;
        if self.threads.len() >= 32 {
            return Err(Error::Budget);
        }
        let owner = Owner::Stack(self.next()?);
        let cap = self
            .memory
            .map(base, size, owner, Permissions::READ_WRITE, false)?;
        let token = Thread(cap);
        self.threads.push(ThreadState {
            token,
            owner,
            head: u32::MAX,
            records: Vec::new(),
        });
        Ok(token)
    }
    pub fn stack_pointer(&self, thread: Thread, address: u32) -> Result<Pointer, Error> {
        self.runnable()?;
        let t = &self.threads[self.thread(thread)?];
        // Range may be uninitialized; pointer formation does not authorize reads.
        let pointer = Pointer {
            cap: t.token.0,
            owner: t.owner,
            address,
        };
        self.range(pointer, 1)?;
        Ok(pointer)
    }
    pub fn module_pointer(
        &self,
        module: Module,
        address: u32,
        code: bool,
    ) -> Result<Pointer, Error> {
        self.runnable()?;
        let m = &self.images[self.image(module)?];
        let cap = if code { m.code } else { m.data };
        self.memory.prove_read(cap, m.owner, address, 1)?;
        Ok(Pointer {
            cap,
            owner: m.owner,
            address,
        })
    }
    // Space's proof API checks complete ranges and identity, but intentionally
    // requires initialization. New stack destinations need a separate range check.
    fn range(&self, pointer: Pointer, size: u32) -> Result<(), Error> {
        self.memory.validate(pointer.cap, pointer.owner)?;
        self.memory
            .validate_range(pointer.cap, pointer.owner, pointer.address, size)?;
        Ok(())
    }
    pub fn offset(&self, p: Pointer, offset: u32) -> Result<Pointer, Error> {
        self.runnable()?;
        let q = Pointer {
            address: p.address.checked_add(offset).ok_or(Fault::Range)?,
            ..p
        };
        self.range(q, 1)?;
        Ok(q)
    }
    pub fn read(&self, p: Pointer, size: u32) -> Result<&[u8], Error> {
        self.runnable()?;
        self.range(p, size)?;
        Ok(self.memory.read(p.address, size)?)
    }
    pub fn write(&mut self, p: Pointer, bytes: &[u8]) -> Result<(), Error> {
        self.runnable()?;
        let size = u32::try_from(bytes.len()).map_err(|_| Error::Budget)?;
        self.range(p, size)?;
        self.memory.write(p.address, bytes)?;
        self.cells
            .retain(|c| !overlaps(c.destination.address, 4, p.address, size));
        if self.threads.iter().any(|t| {
            t.records.iter().any(|r| {
                overlaps(r.pointer.address, 16, p.address, size)
                    || overlaps(r.guard.address, 4, p.address, size)
            })
        }) {
            // Preserve the physical write, but never continue using invalid proof.
            self.pending = true;
        }
        Ok(())
    }
    pub fn establish_cookie(&mut self, module: Module, bits: u32) -> Result<(), Error> {
        self.runnable()?;
        let i = self.image(module)?;
        if self
            .threads
            .iter()
            .any(|t| t.records.iter().any(|r| r.module == module))
        {
            return Err(Error::Active);
        }
        let version = self.images[i].version.checked_add(1).ok_or(Error::Budget)?;
        let mut bytes = [0; 8];
        bytes[..4].copy_from_slice(&bits.to_le_bytes());
        bytes[4..].copy_from_slice(&(!bits).to_le_bytes());
        self.memory.write(self.images[i].cookie_address, &bytes)?;
        self.images[i].value = Some(bits);
        self.images[i].version = version;
        Ok(())
    }
    pub fn encode(&self, module: Module, target: Pointer) -> Result<Encoded, Error> {
        self.runnable()?;
        let m = &self.images[self.image(module)?];
        if target.cap != m.data || target.owner != m.owner {
            return Err(Error::Identity);
        }
        self.memory
            .prove_read(target.cap, target.owner, target.address, 4)?;
        let bits = m.value.ok_or(Error::Unknown)?;
        let actual = self.memory.read(m.cookie_address, 8)?;
        if actual[..4] != bits.to_le_bytes() || actual[4..] != (!bits).to_le_bytes() {
            return Err(Error::Corrupt);
        }
        Ok(Encoded {
            target,
            module,
            version: m.version,
            bits: target.address ^ bits,
        })
    }
    fn encoded(&self, value: Encoded) -> Result<(), Error> {
        if self.encode(value.module, value.target)? != value {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    pub fn store_pointer(&mut self, destination: Pointer, value: Pointer) -> Result<(), Error> {
        self.runnable()?;
        self.range(value, 1)?;
        self.typed_store(destination, Value::Pointer(value), value.address)
    }
    pub fn store_encoded(&mut self, destination: Pointer, value: Encoded) -> Result<(), Error> {
        self.runnable()?;
        self.encoded(value)?;
        self.typed_store(destination, Value::Encoded(value), value.bits)
    }
    /// Store the separately proven cookie XOR EBP relation. Frame construction
    /// still belongs to lifted instructions, not this component.
    pub fn store_guard(
        &mut self,
        destination: Pointer,
        module: Module,
        frame: Pointer,
    ) -> Result<(), Error> {
        self.runnable()?;
        if destination.cap != frame.cap || !matches!(frame.owner, Owner::Stack(_)) {
            return Err(Error::Identity);
        }
        self.range(frame, 4)?;
        let m = &self.images[self.image(module)?];
        let bits = m.value.ok_or(Error::Unknown)? ^ frame.address;
        let value = Value::Guard {
            module,
            version: m.version,
            frame,
        };
        self.typed_store(destination, value, bits)
    }
    fn typed_store(&mut self, destination: Pointer, value: Value, bits: u32) -> Result<(), Error> {
        if self.cells.len() >= 256 {
            return Err(Error::Budget);
        }
        self.write(destination, &bits.to_le_bytes())?;
        if !self.pending {
            self.cells.push(Cell { destination, value });
        }
        Ok(())
    }
    fn cell(&self, destination: Pointer) -> Option<Value> {
        self.cells
            .iter()
            .find(|c| c.destination == destination)
            .map(|c| c.value)
    }
    fn word(&self, p: Pointer) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.read(p, 4)?.try_into().unwrap()))
    }
    fn validate_record(&self, r: Record, previous: Option<Pointer>) -> Result<(), Error> {
        self.encoded(r.scope)?;
        let m = &self.images[self.image(r.module)?];
        let frame = self.offset(r.pointer, 16)?;
        if self.cell(r.guard)
            != Some(Value::Guard {
                module: r.module,
                version: m.version,
                frame,
            })
            || self.word(r.guard)? != (m.value.ok_or(Error::Unknown)? ^ frame.address)
        {
            return Err(Error::Corrupt);
        }
        if r.handler.cap != m.code || r.handler.owner != m.owner {
            return Err(Error::Identity);
        }
        self.memory
            .prove_read(r.handler.cap, r.handler.owner, r.handler.address, 1)?;
        let raw = self.read(r.pointer, 16)?;
        let expected = [
            previous.map_or(u32::MAX, |p| p.address),
            r.handler.address,
            r.scope.bits,
            u32::MAX - 1,
        ];
        for (bytes, word) in raw.as_chunks::<4>().0.iter().zip(expected) {
            if *bytes != word.to_le_bytes() {
                return Err(Error::Corrupt);
            }
        }
        if previous.is_some_and(|p| self.cell(r.pointer) != Some(Value::Pointer(p)))
            || self.cell(self.offset(r.pointer, 4)?) != Some(Value::Pointer(r.handler))
            || self.cell(self.offset(r.pointer, 8)?) != Some(Value::Encoded(r.scope))
        {
            return Err(Error::Unknown);
        }
        Ok(())
    }
    /// Validate bytes actually written by a future lifted prolog. This does not
    /// synthesize that prolog, its saved registers, flags, or handler.
    pub fn register(
        &mut self,
        thread: Thread,
        record: Pointer,
        module: Module,
        handler: Pointer,
        scope: Encoded,
    ) -> Result<(), Error> {
        self.runnable()?;
        let i = self.thread(thread)?;
        let t = &self.threads[i];
        if record.cap != t.token.0 || record.owner != t.owner || scope.module != module {
            return Err(Error::Identity);
        }
        if t.records.len() >= 64 {
            return Err(Error::Budget);
        }
        if self.threads.iter().any(|t| {
            t.records
                .iter()
                .any(|r| overlaps(r.pointer.address, 16, record.address, 16))
        }) {
            return Err(Error::Active);
        }
        let frame = self.offset(record, 16)?;
        let version = self.images[self.image(module)?].version;
        let guards: Vec<_> = self
            .cells
            .iter()
            .filter(|c| {
                c.value
                    == Value::Guard {
                        module,
                        version,
                        frame,
                    }
            })
            .collect();
        if guards.len() != 1 {
            return Err(Error::Unknown);
        }
        let guard = guards[0].destination;
        if guard.cap != record.cap
            || overlaps(record.address, 16, guard.address, 4)
            || self.threads.iter().any(|t| {
                t.records.iter().any(|r| {
                    overlaps(r.pointer.address, 16, guard.address, 4)
                        || overlaps(r.guard.address, 4, guard.address, 4)
                        || overlaps(r.guard.address, 4, record.address, 16)
                })
            })
        {
            return Err(Error::Active);
        }
        let r = Record {
            pointer: record,
            module,
            scope,
            handler,
            guard,
        };
        self.validate_record(r, t.records.last().map(|r| r.pointer))?;
        self.threads[i].records.push(r);
        self.threads[i].head = record.address;
        Ok(())
    }
    pub fn restore(&mut self, thread: Thread, record: Pointer) -> Result<(), Error> {
        self.runnable()?;
        let i = self.thread(thread)?;
        let t = &self.threads[i];
        let last = *t.records.last().ok_or(Error::Unknown)?;
        if last.pointer != record || t.head != record.address {
            return Err(Error::Identity);
        }
        let previous = t.records.iter().rev().nth(1).map(|r| r.pointer);
        self.validate_record(last, previous)?;
        self.threads[i].records.pop();
        self.threads[i].head = previous.map_or(u32::MAX, |p| p.address);
        Ok(())
    }
    pub fn retire_thread(&mut self, thread: Thread) -> Result<(), Error> {
        self.runnable()?;
        let i = self.thread(thread)?;
        if !self.threads[i].records.is_empty() {
            return Err(Error::Active);
        }
        self.memory.release(thread.0, self.threads[i].owner)?;
        self.threads.remove(i);
        self.cells.retain(|c| c.destination.cap != thread.0);
        Ok(())
    }
    pub fn retire_module(&mut self, module: Module) -> Result<(), Error> {
        self.runnable()?;
        let i = self.image(module)?;
        if self
            .threads
            .iter()
            .any(|t| t.records.iter().any(|r| r.module == module))
        {
            return Err(Error::Active);
        }
        let m = &self.images[i];
        self.memory.release(m.code, m.owner)?;
        self.memory.release(m.data, m.owner)?;
        self.memory.release(m.cookie, m.owner)?;
        self.images.remove(i);
        Ok(())
    }
    pub fn begin_exception(
        &mut self,
        thread: Thread,
        code: u32,
        continuable: bool,
    ) -> Result<Dispatch, Error> {
        self.runnable()?;
        let result = (|| {
            let t = &self.threads[self.thread(thread)?];
            if t.head != t.records.last().map_or(u32::MAX, |r| r.pointer.address) {
                return Err(Error::Corrupt);
            }
            let mut previous = None;
            for &record in &t.records {
                self.validate_record(record, previous)?;
                previous = Some(record.pointer);
            }
            Ok(Dispatch {
                code,
                continuable,
                handlers: t.records.iter().rev().map(|r| r.handler.address).collect(),
            })
        })();
        // Even a corrupt/unrecognized chain cannot fall back to ordinary code.
        self.pending = true;
        result
    }
    pub fn unknown_external_effect(&mut self) {
        self.pending = true;
        self.cells.clear();
    }
    /// Successful valid-pointer API footprint only. All eight output bytes must
    /// belong to the invoking thread's stack. No time/ID value is fabricated.
    /// Invalid pointers reject admission; this does not emulate their AV path.
    pub fn entropy_output(
        &mut self,
        thread: Thread,
        destination: Pointer,
        effect: EntropyOutput,
    ) -> Result<CallEffects, Error> {
        self.runnable()?;
        let t = &self.threads[self.thread(thread)?];
        if destination.cap != t.token.0 || destination.owner != t.owner {
            return Err(Error::Identity);
        }
        let (bytes, eax) = match effect {
            EntropyOutput::FileTime(value) => (value.to_le_bytes(), None),
            EntropyOutput::PerformanceCounter { counter, success } => {
                // BOOL promises nonzero, not exactly one; preserve supplied bits.
                if success == 0 {
                    return Err(Error::Unknown);
                }
                (counter.to_le_bytes(), Some(success))
            }
        };
        self.write(destination, &bytes)?;
        // An output aliasing an active record invalidates ordinary continuation.
        self.runnable()?;
        Ok(CallEffects {
            eax,
            volatile_registers_known: false,
            flags_known: false,
            last_error_known: false,
        })
    }
}

#[cfg(test)]
#[path = "startup_state_tests.rs"]
mod tests;
