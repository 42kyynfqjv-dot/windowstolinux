/* Independently authored, MIT OR Apache-2.0. SUB-560 frozen measurement. */
#include <windows.h>
__declspec(noinline) static unsigned parse(const WCHAR *p, DWORD n) {
    unsigned a = p[0] - L'0';
    if (a > 9) return 202;
    if (n == 2) { unsigned b = p[1] - L'0'; if (b > 9) return 202; a = a * 10 + b; }
    return a;
}
int __stdcall entry(void) {
    WCHAR b[3]; DWORD n = GetEnvironmentVariableW(L"W2L_INPUT", b, 3);
    unsigned a;
    if (!n) return 200;
    if (n > 65) return 203;
    if (n > 2) return 201;
    a = parse(b, n);
    if (a == 202) return 202;
    return (int)((a + 3) * 2);
}
