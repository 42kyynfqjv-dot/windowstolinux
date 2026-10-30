#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
/* Authored observer: never inspect the opaque critical-section bytes. */
struct guarded { DWORD before; CRITICAL_SECTION object; DWORD after; };
int main(int argc, char **argv) {
    struct guarded g;
    DWORD spin, error;
    BOOL ok;
    if (argc != 2 || sizeof(void *) != 4 || sizeof(CRITICAL_SECTION) != 24) return 2;
    spin = (DWORD)strtoul(argv[1], NULL, 10);
    if (spin != 0 && spin != 4000) return 3;
    g.before = 0x13579bdf; g.after = 0x2468ace0;
    SetLastError(0x1234);
    ok = InitializeCriticalSectionEx(&g.object, spin, 0);
    error = GetLastError();
    if (!ok) { printf("{\"initialized\":false,\"error\":%lu}\n", error); return 0; }
    printf("{\"initialized\":true,\"success_last_error\":%lu,\"events\":[1", error);
    EnterCriticalSection(&g.object); printf(",2");
    EnterCriticalSection(&g.object); printf(",2");
    ok = TryEnterCriticalSection(&g.object); printf(",%d", ok ? 3 : 0);
    if (ok) { LeaveCriticalSection(&g.object); printf(",4"); }
    LeaveCriticalSection(&g.object); printf(",4");
    LeaveCriticalSection(&g.object); printf(",4");
    DeleteCriticalSection(&g.object); printf(",5");
    ok = InitializeCriticalSectionEx(&g.object, spin, 0);
    if (!ok) { printf("],\"reinitialized\":false}\n"); return 0; }
    printf(",1"); DeleteCriticalSection(&g.object); printf(",5]");
    printf(",\"reinitialized\":true,\"canaries\":%s}\n",
        g.before == 0x13579bdf && g.after == 0x2468ace0 ? "true" : "false");
    return 0;
}
