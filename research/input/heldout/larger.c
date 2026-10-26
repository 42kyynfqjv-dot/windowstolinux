/* Independently authored, MIT OR Apache-2.0. SUB-560 frozen measurement. */
#include <windows.h>
int __stdcall entry(void) {
    WCHAR b[5]; DWORD n = GetEnvironmentVariableW(L"W2L_INPUT", b, 5);
    unsigned a, x;
    if (!n) return 200;
    if (n > 65) return 203;
    if (n > 4) return 201;
    a = b[0] - L'0'; if (a > 9) return 202;
    if (n >= 2) { x = b[1] - L'0'; if (x > 9) return 202; a += x; }
    if (n >= 3) { x = b[2] - L'0'; if (x > 9) return 202; a += x; }
    if (n >= 4) { x = b[3] - L'0'; if (x > 9) return 202; a += x; }
    return (int)a;
}
