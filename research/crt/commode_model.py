"""Test-only hypothetical ownership frame, never inferred from a returned address."""
from dataclasses import dataclass
@dataclass(frozen=True)
class Pointer:
    process: int
    runtime: str
    generation: int
    address: int
@dataclass
class State:
    process: int = 1
    runtime: str = 'app-ucrt'
    generation: int = 1
    address: int = 0x70001000
    size: int = 4
    value: int | None = 64
    live: bool = True
    exclusive: bool = True
    blocked: bool = False
    frame_proven: bool = False

def write_zero(s,p):
    if s.blocked or not s.frame_proven or not s.exclusive:
        s.blocked=True; s.value=None;return 'blocked'
    if not isinstance(p,Pointer):raise ValueError('pointer token required')
    if any(type(v)!=int or v<=0 for v in [p.process,p.generation,s.process,s.generation]) or type(s.address)!=int or type(p.runtime)!=str or type(s.runtime)!=str or not p.runtime or not s.runtime:raise ValueError('identity widths')
    if not s.live or (p.process,p.runtime,p.generation)!=(s.process,s.runtime,s.generation):raise ValueError('owner/lifetime')
    if type(p.address)!=int or not 0<p.address<=0xfffffffc or p.address%4 or p.address!=s.address or type(s.size)!=int or s.size!=4:raise ValueError('full word')
    # Store does not read prior contents. Only an explicit external frame preserves others.
    s.value=0;return 'stored'
def foreign(s):
    s.blocked=True;s.value=None;s.frame_proven=False
