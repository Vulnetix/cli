~>#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char buf[16];
    strcpy(buf, argv[1]);
    puts(buf);
    return 0;
}
