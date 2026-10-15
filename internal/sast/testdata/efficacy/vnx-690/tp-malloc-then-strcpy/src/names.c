#include <stdlib.h>
#include <string.h>

char *copy_name(const char *name) {
    size_t n = strlen(name) + 1;
    char *buf = malloc(n);
~>    strcpy(buf, name);
    return buf;
}

char *dup_label(const char *label) {
    char *out = strdup(label);
~>    out[0] = 'L';
    return out;
}
