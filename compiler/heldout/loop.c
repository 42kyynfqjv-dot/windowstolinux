/* Authored measurement source, MIT OR Apache-2.0. */
volatile unsigned int limit = 5;
int __stdcall entry(void) {
    unsigned int total = 0, i;
    for (i = 0; i < limit; ++i) total += i;
    return (int)total;
}
