/* Independently authored, MIT OR Apache-2.0. SUB-560 frozen measurement. */
#include <windows.h>
__declspec(noinline) static unsigned digit(const WCHAR *p) {
    unsigned x = *p - L'0'; return x <= 9 ? x : 202;
}
__declspec(noinline) static unsigned parse(const WCHAR *p, DWORD n) {
    unsigned a = digit(p), b;
    if (a == 202) return 202;
    if (n == 1) return a;
    b = digit(p + 1);
    return b == 202 ? 202 : a * 10 + b;
}
int __stdcall entry(void) {
    WCHAR b[3]; DWORD n = GetEnvironmentVariableW(L"W2L_INPUT", b, 3);
    if (!n) return 200;
    if (n > 65) return 203;
    if (n > 2) return 201;
    return (int)parse(b, n);
}
