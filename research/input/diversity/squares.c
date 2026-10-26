/* Independently authored, MIT OR Apache-2.0. Frozen SUB-553. */
#include <windows.h>
int __stdcall entry(void) {
    WCHAR buffer[3];
    DWORD n = GetEnvironmentVariableW(L"W2L_INPUT", buffer, 3);
    unsigned result;
    if (n == 0) return 200;
    if (n > 65) return 203;
    if (n > 2) return 201;
    if (buffer[0] < L'0' || buffer[0] > L'9') return 202;
    result = (buffer[0] - L'0') * (buffer[0] - L'0');
    if (n == 2) {
        if (buffer[1] < L'0' || buffer[1] > L'9') return 202;
        result += (buffer[1] - L'0') * (buffer[1] - L'0');
    }
    return (int)result;
}
