"""Test-only process-contract model; no PE admission or Windows API implementation."""
from dataclasses import dataclass


class Reject(ValueError):
    pass


def span(address, size):
    if type(address) is not int or type(size) is not int:
        raise Reject('integer range')
    if not 0 < size <= 65536 or not 0 < address < 2**32 or address + size > 2**32:
        raise Reject('range/budget')
    return address + size


@dataclass
class Region:
    base: int
    size: int
    owner: str
    generation: int
    writable: bool
    data: bytearray
    defined: list


class Space:
    def __init__(self):
        self.regions = {}
        self.serial = 0

    def map(self, base, size, owner, *, zero=False, writable=True):
        end = span(base, size)
        if len(self.regions) >= 16 or sum(r.size for r in self.regions.values()) + size > 65536:
            raise Reject('space budget')
        if any(base < r.base + r.size and r.base < end for r in self.regions.values()):
            raise Reject('overlap')
        self.serial += 1
        self.regions[base] = Region(base, size, owner, self.serial, writable,
                                    bytearray(size), [zero] * size)
        return (base, self.serial, owner)  # proof capability, NOT guest pointer bits

    def access(self, address, size, write=False):
        end = span(address, size)
        found = [r for r in self.regions.values() if r.base <= address and end <= r.base+r.size]
        if len(found) != 1:
            raise Reject('unmapped or crossing region')
        r = found[0]
        if write and not r.writable:
            raise Reject('permission')
        return r, address-r.base

    def read(self, address, size):
        r, i = self.access(address, size)
        if not all(r.defined[i:i+size]):
            raise Reject('uninitialized: outside admitted domain')
        return bytes(r.data[i:i+size])

    def write(self, address, data):
        r, i = self.access(address, len(data), True)
        r.data[i:i+len(data)] = data
        r.defined[i:i+len(data)] = [True]*len(data)

    def capability(self, token):
        base, generation, owner = token
        r = self.regions.get(base)
        if r is None or (r.generation, r.owner) != (generation, owner):
            raise Reject('stale/wrong owner proof')
        return r

    def release(self, token):
        r = self.capability(token)
        del self.regions[r.base]

    def move_resize(self, token, destination, size, *, fail=False, zero_tail=False):
        """Selected moving-success/NULL-failure outcomes, not an allocator policy."""
        old = self.capability(token)
        span(destination, size)
        if fail:
            return None  # failure does not free or alter original
        fresh = self.map(destination, size, old.owner, zero=zero_tail)
        new = self.capability(fresh)
        n = min(old.size, size)
        new.data[:n], new.defined[:n] = old.data[:n], old.defined[:n]
        self.release(token)
        return fresh

    def external(self, effect, address, capacity, payload=b'', count=0):
        """Two independently specified outcomes; unknown effects cannot compose."""
        if effect not in ('unchanged_failure', 'prefix_success'):
            raise Reject('unresolved external effect')
        r, i = self.access(address, capacity, True)
        if effect == 'unchanged_failure':
            return False
        if type(count) is not int or not 0 <= count <= capacity or len(payload) != count:
            raise Reject('backend count')
        # Invalidate proof facts across the whole borrow before defining the prefix.
        # Unwritten physical bytes remain intact, but old initialization is not proof
        # of data belonging to the new read epoch.
        r.defined[i:i+capacity] = [False]*capacity
        if count:
            self.write(address, payload)
        return True


class Module:
    def __init__(self, callbacks):
        self.callbacks = tuple(callbacks)
        self.position = 0
        self.state = 'mapped'

    def bind(self, dependencies_ready):
        if self.state != 'mapped' or not dependencies_ready:
            raise Reject('dependency/binding phase')
        self.state = 'initializing'

    def complete(self, callback, success):
        if self.state != 'initializing' or self.position >= len(self.callbacks):
            raise Reject('callback phase')
        if callback != self.callbacks[self.position]:
            raise Reject('callback order')
        if not success:
            self.state = 'failed'  # no invented rollback of earlier effects
        else:
            self.position += 1

    def enter(self):
        if self.state != 'initializing' or self.position != len(self.callbacks):
            raise Reject('startup incomplete')
        self.state = 'running'
