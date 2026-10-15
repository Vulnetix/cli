#include <stdlib.h>
#include <string.h>

char *pick(const char *a, const char *b) {
~>    char *s = strdup(a);
    if (strlen(b) > strlen(a)) {
        s = strdup(b);
    }
    return s;
}

void scratch(size_t n) {
~>    int *tmp = malloc(n * sizeof(int));
    memset(tmp, 0, n * sizeof(int));
    tmp = calloc(n, sizeof(int));
    free(tmp);
}
