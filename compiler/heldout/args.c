/* Authored measurement source, MIT OR Apache-2.0. */
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc != 3) return 99;
    return fwrite("Args", 1, 4, stdout) == 4 ? argc + (unsigned char)argv[1][0] : 99;
}
