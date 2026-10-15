#include <stdlib.h>

int line_grow(struct line *ln, size_t want)
{
    char *nbuf;

    nbuf = reallocarray(ln->data, want, 2);
    if (nbuf == NULL) {
        return -1;
    }
~>  ln->data[0] = '\0';
    ln->data = nbuf;
    return 0;
}
