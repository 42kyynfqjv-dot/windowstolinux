"""Read-only owned-child Windows timeout observer; parent enforces a 3s budget.

Independent implementation from Microsoft contracts: GetThreadWaitChain,
OpenThreadWaitChainSession, GetProcessTimes and Tool Help thread/module snapshots.
https://learn.microsoft.com/windows/win32/api/wct/nf-wct-getthreadwaitchain
https://learn.microsoft.com/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
No debugger, suspension, privilege changes, remote memory reads or retries.
WCT flags=0 stops traversal at the first other-process thread. Microsoft requires
SE_DEBUG_NAME for WCT; this observer never enables it. Access-denied failures or
NoAccess nodes are useful limits, not proof of a wait cause. WCT is not a stack
trace; neither it nor module ranges establishes the current instruction pointer.
Output is JSON lines with partial milestones followed by the complete record.
Identity comes from CPython Popen's retained handle and GetProcessTimes; PID alone
is insufficient. Tool Help lists system thread IDs/owners but only matching owned
threads are inspected. Module snapshot bitness/access/transient errors are data.
"""
import ctypes as C
import json
import os
import sys

MAX_THREADS = 128
MAX_MODULES = 512


def observe(api, pid, creation, progress=lambda record: None):
    """Never enumerate/query details before matching the retained child's identity."""
    result = {"pid": pid, "expected_creation_time": creation, "observer": "wct-toolhelp-v1"}
    identity = api.identity()
    result["identity"] = identity
    if identity["pid"] != pid or identity["creation_time"] != creation:
        result["error"] = "owned process identity mismatch; no observation performed"
        return result
    if not identity["alive"]:
        result["error"] = "owned process exited; no observation performed"
        return result
    result["identity_verified"] = True
    progress({"stage": "identity", "identity": identity})
    for name, operation in (("modules", api.modules), ("threads", api.threads)):
        try:
            result[name] = operation()
        except OSError as error:
            result[name] = {"error": str(error), "winerror": getattr(error, "winerror", None),
                            "operation": getattr(error, "operation", None)}
        progress({"stage": name, "result": result[name]})
    return result


class WindowsAPI:
    def __init__(self, pid):
        if os.name != "nt":
            raise OSError("Windows observer unavailable on this platform")
        self.pid = pid
        self.k = C.WinDLL("kernel32", use_last_error=True)
        self.a = C.WinDLL("advapi32", use_last_error=True)
        self.D = C.c_uint32
        self.B = C.c_int32
        H = C.c_void_p
        def bind(dll, name, restype, args):
            f = getattr(dll, name); f.restype = restype; f.argtypes = args
            return f
        D, B = self.D, self.B
        self.open_process = bind(self.k, "OpenProcess", H, [D, B, D])
        self.close = bind(self.k, "CloseHandle", B, [H])
        self.process_id = bind(self.k, "GetProcessId", D, [H])
        self.times = bind(self.k, "GetProcessTimes", B, [H] + [C.POINTER(C.c_uint64)] * 4)
        self.wait = bind(self.k, "WaitForSingleObject", D, [H, D])
        self.handle_count = bind(self.k, "GetProcessHandleCount", B, [H, C.POINTER(D)])
        self.snapshot = bind(self.k, "CreateToolhelp32Snapshot", H, [D, D])
        self.open_thread = bind(self.k, "OpenThread", H, [D, B, D])
        self.thread_owner = bind(self.k, "GetProcessIdOfThread", D, [H])
        self.open_session = bind(self.a, "OpenThreadWaitChainSession", H, [D, H])
        self.close_session = bind(self.a, "CloseThreadWaitChainSession", None, [H])
        class Thread(C.Structure):
            _fields_ = [("size", D), ("usage", D), ("tid", D), ("pid", D),
                        ("base", C.c_int32), ("delta", C.c_int32), ("flags", D)]
        class Module(C.Structure):
            _fields_ = [("size", D), ("id", D), ("pid", D), ("global_usage", D),
                        ("process_usage", D), ("base", H), ("length", D), ("module", H),
                        ("name", C.c_wchar * 256), ("path", C.c_wchar * 260)]
        class Lock(C.Structure):
            _fields_ = [("name", C.c_wchar * 128), ("timeout", C.c_int64), ("alertable", B)]
        class ThreadNode(C.Structure):
            _fields_ = [("pid", D), ("tid", D), ("wait_ms", D), ("switches", D)]
        class Payload(C.Union):
            _fields_ = [("lock", Lock), ("thread", ThreadNode)]
        class Node(C.Structure):
            _fields_ = [("type", C.c_int32), ("status", C.c_int32), ("data", Payload)]
        self.Thread, self.Module, self.Node = Thread, Module, Node
        self.thread_first = bind(self.k, "Thread32First", B, [H, C.POINTER(Thread)])
        self.thread_next = bind(self.k, "Thread32Next", B, [H, C.POINTER(Thread)])
        self.module_first = bind(self.k, "Module32FirstW", B, [H, C.POINTER(Module)])
        self.module_next = bind(self.k, "Module32NextW", B, [H, C.POINTER(Module)])
        self.chain = bind(self.a, "GetThreadWaitChain", B,
                          [H, C.c_size_t, D, D, C.POINTER(D), C.POINTER(Node), C.POINTER(B)])
        self.handle = self.open_process(0x101000, False, pid)  # QUERY_LIMITED_INFORMATION | SYNCHRONIZE
        if not self.handle:
            raise C.WinError(C.get_last_error())

    def identity(self):
        times = [C.c_uint64() for _ in range(4)]
        if not self.times(self.handle, *(C.byref(t) for t in times)):
            raise C.WinError(C.get_last_error())
        state = self.wait(self.handle, 0)
        if state not in (0, 258):  # WAIT_OBJECT_0 / WAIT_TIMEOUT
            raise C.WinError(C.get_last_error())
        handles = self.D()
        count_ok = self.handle_count(self.handle, C.byref(handles))
        return {"pid": self.process_id(self.handle), "creation_time": times[0].value,
                "alive": state == 258, "cpu_seconds": (times[2].value + times[3].value) / 10_000_000,
                "handles": handles.value if count_ok else None}

    def entries(self, flags, cls, first, next_entry, limit, owned_only=False):
        snap = self.snapshot(flags, self.pid if flags != 4 else 0)
        if snap == C.c_void_p(-1).value:
            error = C.WinError(C.get_last_error())
            error.operation = "CreateToolhelp32Snapshot"
            raise error
        rows = []
        try:
            row = cls(); row.size = C.sizeof(cls)
            ok = first(snap, C.byref(row))
            while ok:
                if not owned_only or row.pid == self.pid:
                    if len(rows) >= limit:
                        raise OSError("bounded snapshot entry limit exceeded")
                    rows.append(cls.from_buffer_copy(row))
                row.size = C.sizeof(cls)
                ok = next_entry(snap, C.byref(row))
            error = C.get_last_error()
            if error != 18:  # ERROR_NO_MORE_FILES
                raise C.WinError(error)
            return rows
        finally:
            self.close(snap)

    def threads(self):
        # Tool Help enumerates thread ownership metadata; inspect only matching PID.
        rows = self.entries(4, self.Thread, self.thread_first, self.thread_next, MAX_THREADS, True)
        session = self.open_session(0, None)  # synchronous, in-process traversal only
        if not session:
            raise C.WinError(C.get_last_error())
        result = []
        try:
            for row in rows:
                item = {"tid": row.tid}; result.append(item)
                handle = self.open_thread(0x0800, False, row.tid)
                if not handle:
                    error = C.get_last_error()
                    item.update(error=str(C.WinError(error)), winerror=error); continue
                try:
                    if self.thread_owner(handle) != self.pid:
                        item["error"] = "thread ownership changed; not queried"; continue
                    nodes = (self.Node * 16)(); count = self.D(16); cycle = self.B()
                    if not self.chain(session, 0, 0, row.tid, C.byref(count), nodes, C.byref(cycle)):
                        error = C.get_last_error()
                        item.update(error=str(C.WinError(error)), winerror=error); continue
                    item["cycle"] = bool(cycle.value)
                    item["nodes"] = []
                    for node in nodes[:min(count.value, 16)]:
                        data = {"object_type": node.type, "object_status": node.status}
                        if node.type == 8:  # WctThreadType
                            if node.data.thread.pid != self.pid:
                                data["external_boundary"] = True
                            else:
                                data.update(tid=node.data.thread.tid, wait_ms=node.data.thread.wait_ms,
                                            context_switches=node.data.thread.switches)
                        item["nodes"].append(data)
                finally:
                    self.close(handle)
            return result
        finally:
            self.close_session(session)

    def modules(self):
        rows = self.entries(0x18, self.Module, self.module_first, self.module_next, MAX_MODULES)
        return [{"name": row.name, "base": row.base, "size": row.length} for row in rows]

    def finish(self):
        self.close(self.handle)


def main():
    api = None
    try:
        pid, creation = map(int, sys.argv[1:])
        if pid <= 0 or creation <= 0:
            raise ValueError("positive owned PID and creation time required")
        api = WindowsAPI(pid)
        print(json.dumps(observe(api, pid, creation,
                                 lambda record: print(json.dumps(record), flush=True))), flush=True)
    except Exception as error:
        print(json.dumps({"error": type(error).__name__ + ": " + str(error)}), flush=True)
    finally:
        if api is not None:
            api.finish()


if __name__ == "__main__":
    main()
