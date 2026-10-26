/* Authored measurement source, MIT OR Apache-2.0. */
int __stdcall entry(void) {
    volatile unsigned char data[2];
    data[0] = 'A'; data[1] = 'B'; data[1] += 1;
    return data[0] + data[1];
}
