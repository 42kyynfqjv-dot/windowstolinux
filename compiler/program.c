/* Independently authored WindowsToLinux fixture, MIT OR Apache-2.0. */
#ifdef FREESTANDING
__declspec(dllimport) int __cdecl _write(int, const void *, unsigned int);
#else
#include <io.h>
#endif

__declspec(noinline) int helper(int left, int right) {
    return left + right;
}

static int program(void) {
    const int value = helper(7, 5);
    const int written = _write(1, "Hello", 5);
    return value == 12 && written == 5 ? 0 : 99;
}

#ifdef FREESTANDING
int __stdcall entry(void) { return program(); }
#else
int main(void) { return program(); }
#endif
