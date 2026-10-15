#include <stddef.h>

long sum(const int *v, size_t n) {
    long total = 0;
    size_t i = 0;
    if (n == 0) {
        goto done;
    }
  next:
    total += v[i];
    i++;
~>    if (i < n) goto  next ;
done:
    return total;
}

int skip_spaces(const char *s) {
    int i = 0;
again:
    if (s[i] == ' ') {
        i++;
~>        goto again;
    }
    return i;
}
