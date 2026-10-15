#include <stdlib.h>

int main(int argc, char **argv) {
~>    char *p = (char *)strtoul(argv[1], NULL, 16);
    *p = 0;
~>    void (*fn)(void) = (void (*)(void))strtoull(argv[2], 0, 0);
    fn();
~>    int *q = (int *)(uintptr_t)atol(getenv("TARGET"));
    return *q;
}
