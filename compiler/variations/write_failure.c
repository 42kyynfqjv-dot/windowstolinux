/* Independently authored WindowsToLinux fixture, MIT OR Apache-2.0. */
__declspec(dllimport) int __cdecl _write(int, const void *, unsigned int);
__declspec(noinline) int helper(int left, int right) {
    return left + right;
}

int __stdcall entry(void) {
    const int value = helper(7, 5);
    const int written = _write(1, "Hello", 5);
    return value == 12 && written == 6 ? 0 : 99;
}
