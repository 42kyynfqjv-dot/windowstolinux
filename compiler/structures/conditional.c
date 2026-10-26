/* Independently authored fixture, MIT OR Apache-2.0. */
__declspec(dllimport) int __cdecl _write(int, const void *, unsigned int);
__declspec(noinline) int helper(int a, int b) {
    return a < b ? a + b : a + 1;
}
int __stdcall entry(void) {
    const int first = helper(7, 5);
    const int second = helper(3, 4);
    const int written = _write(1, "Branch", 6);
    /* Actual results8 and7: deliberately take the failure outcome. */
    return first == 9 && second == 7 && written == 6 ? 0 : 99;
}
