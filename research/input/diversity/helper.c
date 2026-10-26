/* Independently authored freestanding experiment, MIT OR Apache-2.0. */
#include <windows.h>
__declspec(noinline) static unsigned decimal(const WCHAR *buffer, DWORD n) {
    unsigned result;
    if (buffer[0] < L'0' || buffer[0] > L'9') return 202;
    result = buffer[0] - L'0';
    if (n == 2) {
        if (buffer[1] < L'0' || buffer[1] > L'9') return 202;
        result = 10 * result + buffer[1] - L'0';
    }
    return result;
}
int __stdcall entry(void) {
    WCHAR buffer[3];
    DWORD n = GetEnvironmentVariableW(L"W2L_INPUT", buffer, 3);
    if (!n) return 200;
    if (n > 65) return 203;
    if (n > 2) return 201;
    return (int)decimal(buffer, n);
}
