/* Independently authored fixture, MIT OR Apache-2.0. */
__declspec(dllimport) int __cdecl _write(int, const void *, unsigned int);
__declspec(noinline) int inner(int a, int b) { return a + b; }
__declspec(noinline) int outer(int a, int b) {
    const int intermediate = inner(a, b);
    if (intermediate != 12) return 99;
    return inner(intermediate, 3);
}
int __stdcall entry(void) {
    const int value = outer(7, 5);
    const int written = _write(1, "Nested", 6);
    return value == 15 && written == 6 ? 0 : 99;
}
