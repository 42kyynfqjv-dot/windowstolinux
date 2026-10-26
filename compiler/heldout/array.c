/* Authored measurement source, MIT OR Apache-2.0. */
volatile unsigned int values[3] = {2, 3, 4};
int __stdcall entry(void) { return (int)(values[0] + values[1] + values[2]); }
