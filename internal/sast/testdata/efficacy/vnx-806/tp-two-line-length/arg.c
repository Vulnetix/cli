#include <string.h>

int main(int argc, char **argv) {
    char local[32];
    const char *arg = argv[1];
    size_t n = strlen(arg);
~>    memcpy(local, arg, n);
    local[n] = '\0';
    return 0;
}
