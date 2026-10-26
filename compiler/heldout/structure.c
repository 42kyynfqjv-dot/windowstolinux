/* Authored measurement source, MIT OR Apache-2.0. */
struct Pair { unsigned int a; unsigned int b; };
int __stdcall entry(void) {
    volatile struct Pair pair;
    pair.a = 7; pair.b = 5;
    return (int)(pair.a + pair.b);
}
