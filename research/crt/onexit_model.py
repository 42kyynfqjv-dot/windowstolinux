"""SUB-542 test-only abstract ownership contract, not CRT emulation or PE execution.
Foreign effects below are explicit hypothetical test premises, never inferred from
an import's numeric result or a successful Windows probe.
"""
from dataclasses import dataclass, field

@dataclass
class Table:
    owner: int
    start: int
    size: int = 12
    words: tuple = (0, 0, 0)
    life: str = 'fresh'
    callbacks: list = field(default_factory=list)

@dataclass
class State:
    owner: int = 1
    flag: int | None = 0
    mode: int | None = 1
    tables: list = field(default_factory=lambda: [Table(1, 0x30ac), Table(1, 0x30b8)])
    blocked: bool = False
    terminal: bool = False
    isolated: bool = True
    events: list = field(default_factory=list)
    process_callbacks: list | None = field(default_factory=list)

@dataclass(frozen=True)
class Foreign:
    result: int | None = None
    # An explicit model-only frame premise. Real CRT imports have no such proof yet.
    framed: bool = False
    words: tuple | None = None
    nonreturn: bool = False

@dataclass(frozen=True)
class Result:
    kind: str
    eax: int | None = None
    known_mask: int = 0


def validate(s):
    if not s.isolated:
        raise ValueError('ownership/valid-stack premise missing')
    if len(s.tables) != 2:
        raise ValueError('two tables required')
    # Exact current image profile; prevents partial/mixed/protected/foreign ownership.
    for table, address in zip(s.tables, (0x30ac, 0x30b8)):
        if table.owner != s.owner or table.start != address or table.size != 12:
            raise ValueError('table owner/full range/protected alias')
        if len(table.words) != 3 or any(v is not None and not 0 <= v <= 0xffffffff for v in table.words):
            raise ValueError('word range')
    if s.flag is not None and not 0 <= s.flag <= 255:
        raise ValueError('flag byte')
    if s.mode is not None and not 0 <= s.mode <= 0xffffffff:
        raise ValueError('mode word')


def block(s, event):
    s.events.append(event)
    s.blocked = True
    s.flag = s.mode = None
    s.process_callbacks = None
    for t in s.tables:
        t.words = (None, None, None)
        t.life = 'unknown'
        t.callbacks.clear()
    return Result('blocked')


def foreign(s, t, f, name):
    s.events.append(name)
    if not f.framed or f.result is None or f.nonreturn:
        # Numeric success/failure alone never grants a frame or preserves disjoint words.
        return block(s, 'unresolved foreign effects/nonreturn')
    if not 0 <= f.result <= 0xffffffff:
        raise ValueError('foreign result must be x86 bits')
    if t is not None:
        if f.words is None or len(f.words) != 3 or any(not isinstance(v, int) or not 0 <= v <= 0xffffffff for v in f.words):
            return block(s, 'unknown foreign table writes')
        t.words = f.words
        t.life = 'opaque-ready' if f.result == 0 else 'unknown'
        t.callbacks.clear()
    return f.result


def initialize(s, policy, *, incoming_eax=None, effects=()):
    validate(s)
    if s.blocked:
        return Result('blocked')
    if s.terminal:
        return Result('nonreturn')
    if s.flag is None:
        return block(s, 'unknown initialization byte')
    if s.flag:
        # Actual branch precedes policy validation and does not consume table contents.
        return Result('returned', 1 if incoming_eax is None else (incoming_eax & 0xffffff00) | 1,
                      0xff if incoming_eax is None else 0xffffffff)
    if policy is None:
        return block(s, 'unknown policy')
    if not isinstance(policy, int) or not 0 <= policy <= 0xffffffff:
        raise ValueError('policy bits')
    if policy not in (0, 1):
        s.terminal = True
        s.events.append('fastfail-request:5')
        return Result('fastfail-request')
    if s.mode is None:
        return block(s, 'unknown mode read')
    if s.mode == 0 or policy == 1:
        for t in s.tables:
            # Writes do not read the prior contents; all 24 bytes gain initialization.
            t.words = (0xffffffff,) * 3
            t.life = 'sentinel'
            t.callbacks.clear()
        s.flag = 1
        s.events.append('six sentinel stores; flag=1')
        return Result('returned', 1, 0xffffffff)
    for i, t in enumerate(s.tables):
        f = effects[i] if i < len(effects) else Foreign()
        result = foreign(s, t, f, f'initialize-table-{i}')
        if isinstance(result, Result):
            return result
        if result != 0:
            # XOR AL,AL preserves the import return's upper 24 bits.
            return Result('returned', result & 0xffffff00, 0xffffffff)
    s.flag = 1
    return Result('returned', 1, 0xffffffff)


def conversion(callback_bits, result_bits):
    if not 0 <= callback_bits <= 0xffffffff or not 0 <= result_bits <= 0xffffffff:
        raise ValueError('x86 scalar range')
    # Independent specification of the CMOVE/NEG/SBB/NEG/LEA result.
    success = callback_bits != 0 and result_bits == 0
    return (0 if success else 0xffffffff, 1 if success else 0x44)


def register(s, callback, *, allowed_callbacks, effect=Foreign()):
    validate(s)
    if s.blocked:
        return Result('blocked')
    if s.terminal:
        return Result('nonreturn')
    if callback == 0 or callback not in allowed_callbacks:
        raise ValueError('callback lifetime/provenance')
    t = s.tables[0]
    if t.words[0] is None:
        return block(s, 'unknown registration discriminator')
    sentinel = t.words[0] == 0xffffffff
    if not sentinel and t.life != 'opaque-ready':
        return block(s, 'uninitialized/consumed opaque table')
    name = '_crt_atexit' if sentinel else '_register_onexit_function'
    result = foreign(s, None, effect, name)
    if isinstance(result, Result):
        return result
    if not sentinel:
        # Failed registration can mutate table/allocation state: never presume rollback.
        if effect.words is None or len(effect.words) != 3 or any(not isinstance(v, int) or not 0 <= v <= 0xffffffff for v in effect.words):
            return block(s, 'unknown registration writes')
        t.words = effect.words
        if result != 0:
            t.life = 'unknown'
    if sentinel:
        if result != 0:
            s.process_callbacks = None  # Failure does not prove process-queue rollback.
        elif s.process_callbacks is None:
            return block(s, 'unknown process registration queue')
        else:
            s.process_callbacks.append(callback)
    elif result == 0:
        t.callbacks.append(callback)
    return Result('returned', conversion(callback, result)[0], 0xffffffff)


def consume_model_table(s, index):
    """Only model lifecycle, not native callback execution or imported effects."""
    validate(s)
    if s.blocked or s.terminal or s.tables[index].life != 'opaque-ready':
        raise ValueError('table lifetime')
    t = s.tables[index]
    callbacks = list(reversed(t.callbacks))
    t.life = 'consumed'
    t.words = (None, None, None)
    t.callbacks.clear()
    return callbacks
