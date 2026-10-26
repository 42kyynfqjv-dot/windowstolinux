/* Independently authored; MIT OR Apache-2.0. Freestanding custom entry. */
#include <windows.h>
DWORD WINAPI entry(void) {
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    unsigned char buffer[256];
    DWORD count, i, sent, written;
    if (!input || input == INVALID_HANDLE_VALUE || !output || output == INVALID_HANDLE_VALUE) return 10;
    for (;;) {
        if (!ReadFile(input, buffer, sizeof(buffer), &count, NULL)) return 11;
        if (count > sizeof(buffer)) return 14;
        if (!count) return 0;
        for (i = 0; i < count; ++i) {
            if (buffer[i] >= 'a' && buffer[i] <= 'z') buffer[i] -= 'a' - 'A';
        }
        sent = 0;
        while (sent < count) {
            if (!WriteFile(output, buffer + sent, count - sent, &written, NULL)) return 12;
            if (!written || written > count - sent) return 13;
            sent += written;
        }
    }
}
