/* Authored observational probe, MIT OR Apache-2.0. No runtime source imported. */
#include <windows.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    /* Resolve error cells before measurement; this can initialize CRT TLS. */
    volatile int *ep = _errno();
    volatile unsigned long *dp = __doserrno();
    int old_e, after_e[2], *p[2];
    unsigned long old_d, after_d[2];
    DWORD old_l, after_l[2];
    HMODULE owner;
    HANDLE owner_file;
    MEMORY_BASIC_INFORMATION region;
    char path[32768];
    char file_path[32768];
    DWORD n;
    int i;
    if (!ep || !dp) return 90;
    old_e = *ep; old_d = *dp; old_l = GetLastError();
    for (i = 0; i < 2; ++i) {
        *ep = i ? EDOM : 0;
        *dp = i ? ERROR_INVALID_PARAMETER : 0;
        SetLastError(i ? 0x20001234UL : 0);
        p[i] = __p__commode();
        after_l[i] = GetLastError(); /* First observable call after accessor. */
        after_e[i] = *ep; after_d[i] = *dp;
    }
    *ep = old_e; *dp = old_d; SetLastError(old_l);
    /* No dereference or write to the returned word. Metadata only after capture. */
    if (!p[0] || !p[1] || (uintptr_t)p[0] % 4) return 91;
    if (VirtualQuery(p[0], &region, sizeof(region)) != sizeof(region)
        || region.State != MEM_COMMIT || (region.Protect & PAGE_GUARD)
        || (region.Protect & 255) != PAGE_READWRITE
        || (uintptr_t)p[0] < (uintptr_t)region.BaseAddress
        || region.RegionSize < 4
        || (uintptr_t)p[0] - (uintptr_t)region.BaseAddress > region.RegionSize - 4)
        return 92;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
        | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)p[0], &owner)) return 93;
    n = GetModuleFileNameA(owner, path, sizeof(path));
    if (!n || n >= sizeof(path)) return 94;
    /* Resolve redirection in this x86 process before a 64-bit harness hashes it. */
    owner_file = CreateFileA(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (owner_file == INVALID_HANDLE_VALUE) return 95;
    n = GetFinalPathNameByHandleA(owner_file, file_path, sizeof(file_path), FILE_NAME_NORMALIZED);
    CloseHandle(owner_file);
    if (!n || n >= sizeof(file_path)) return 96;
    for (i = 0; i < 2; ++i)
        printf("%d %lu %d %lu %lu %lu\n", i, (unsigned long)(uintptr_t)p[i],
            after_e[i], after_d[i], (unsigned long)after_l[i],
            (unsigned long)(uintptr_t)owner);
    fprintf(stderr, "OWNER\t%s\n", path);
    fprintf(stderr, "OWNER_FILE\t%s\n", file_path);
    return 0; /* Changed error values are observations, not suppressed failures. */
}
