"""Independent test-only dispatch/effect contract, never PE execution authority."""
from dataclasses import dataclass,field
@dataclass
class State:
    values:dict=field(default_factory=dict)
    owned:set=field(default_factory=set)
    trace:list=field(default_factory=list)
    blocked:bool=False

def dispatch(entries, effects, state, *, start, end, code, protected=(), integer=True):
    if start%4 or end<start or end-start!=4*len(entries):raise ValueError('table range')
    if any(start<b and a<end for a,b in protected):raise ValueError('table alias')
    if any(p and p not in code for p in entries):raise ValueError('unowned callback')
    for p in entries:
        if not p:continue
        state.trace.append(p)
        effect=effects.get(p)
        if effect is None:
            state.values={k:None for k in state.values};state.blocked=True;return None
        result,writes=effect
        if any(k not in state.owned for k in writes):raise ValueError('unowned write')
        state.values.update(writes)
        if integer and result is None:state.blocked=True;return None
        if integer and result!=0:return result
    return 0 if integer else None
