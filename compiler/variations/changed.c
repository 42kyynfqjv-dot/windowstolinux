/* Independently authored WindowsToLinux fixture, MIT OR Apache-2.0. */
__declspec(dllimport) int __cdecl _write(int, const void *, unsigned int);
__declspec(noinline) int helper(int left, int right) {
    return left + right;
}

int __stdcall entry(void) {
    const int value = helper(7, 4);
    const int written = _write(1, "Value", 5);
    return value == 11 && written == 5 ? 0 : 99;
}
