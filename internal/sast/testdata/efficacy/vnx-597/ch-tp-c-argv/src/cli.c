#include <stdio.h>

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "run";
~>    if (mode == "debug") {
        puts("debug");
    }
    return 0;
}
