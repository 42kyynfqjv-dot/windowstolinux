#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
/* Authored data-only observer. Only its own temporary allocation is protected. */
int main(int argc, char **argv) {
    SYSTEM_INFO system;
    MEMORY_BASIC_INFORMATION info;
    BYTE *base, *address;
    DWORD old = 0x12345678, ignored, error, protections[3], states[3];
    SIZE_T size, committed;
    int mode, i;
    BOOL ok;
    if (argc != 2 || sizeof(void *) != 4) return 2;
    mode = atoi(argv[1]);
    if (mode < 0 || mode > 5) return 3;
    GetSystemInfo(&system);
    if (system.dwPageSize != 4096) return 4;
    base = VirtualAlloc(NULL, 3 * 4096, MEM_RESERVE, PAGE_READWRITE);
    if (!base) return 5;
    committed = mode == 4 ? 4096 : 3 * 4096;
    if (VirtualAlloc(base, committed, MEM_COMMIT, PAGE_READWRITE) != base) return 6;
    address = base + 4096 + 17; size = 128;
    if (mode == 1 || mode == 2 || mode == 4) { address = base + 4095; size = 2; }
    if (mode == 2 && !VirtualProtect(base, 4096, PAGE_READONLY, &ignored)) return 7;
    SetLastError(0x87654321);
    ok = VirtualProtect(address, size,
        mode == 2 ? PAGE_READWRITE : mode == 3 ? PAGE_NOACCESS : PAGE_READONLY,
        mode == 5 ? NULL : &old);
    error = GetLastError();
    for (i = 0; i < 3; ++i) {
        if (!VirtualQuery(base + i * 4096, &info, sizeof(info))) return 8;
        protections[i] = info.Protect; states[i] = info.State;
    }
    printf("{\"mode\":%d,\"ok\":%s,\"old\":%lu,\"last_error\":%lu,\"pages\":[%lu,%lu,%lu],\"states\":[%lu,%lu,%lu]}\n",
        mode, ok ? "true" : "false", old, error, protections[0], protections[1], protections[2], states[0], states[1], states[2]);
    if (!VirtualFree(base, 0, MEM_RELEASE)) return 9;
    return 0;
}
