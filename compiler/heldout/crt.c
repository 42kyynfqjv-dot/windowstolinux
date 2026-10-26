/* Authored measurement source, MIT OR Apache-2.0. */
#include <stdio.h>
int main(void) { return fwrite("CRT", 1, 3, stdout) == 3 ? 0 : 99; }
