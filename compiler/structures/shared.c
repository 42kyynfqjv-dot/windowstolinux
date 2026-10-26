/* Independently authored fixture, MIT OR Apache-2.0. */
__declspec(dllimport) int __cdecl _write(int, const void *, unsigned int);
__declspec(noinline) int helper(int a, int b) { return a + b; }
int __stdcall entry(void) {
    const int first = helper(7, 5);
    const int second = helper(3, 4);
    const int written = _write(1, "Shared", 6);
    return first == 12 && second == 7 && written == 6 ? 0 : 99;
}
