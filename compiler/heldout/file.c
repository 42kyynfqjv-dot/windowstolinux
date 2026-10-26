/* Authored measurement source, MIT OR Apache-2.0. */
#include <stdio.h>
int main(void) {
    char data[4];
    FILE *file = fopen("held.txt", "wb");
    if (!file) return 99;
    if (fwrite("Data", 1, 4, file) != 4) return 98;
    if (fclose(file)) return 97;
    file = fopen("held.txt", "rb");
    if (!file) return 96;
    if (fread(data, 1, 4, file) != 4) return 95;
    if (fclose(file)) return 94;
    return fwrite(data, 1, 4, stdout) == 4 ? 0 : 93;
}
