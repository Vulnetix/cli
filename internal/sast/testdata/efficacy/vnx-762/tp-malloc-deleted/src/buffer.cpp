#include <cstdlib>
#include <cstring>

void copy(const char *src) {
    char *dst = (char *)malloc(strlen(src) + 1);
    strcpy(dst, src);
~>    delete[] dst;
}

void dup(const char *src) {
    char *d = strdup(src);
    use(d);
~>    delete d;
}
