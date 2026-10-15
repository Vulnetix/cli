#include <stdlib.h>

#define PREFIX_SIZE sizeof(size_t)

void zfree(void *ptr)
{
    void *realptr;
    if (ptr == NULL)
        return;
    realptr = (char *)ptr - PREFIX_SIZE;
    free(realptr);
    free((char *)ptr - PREFIX_SIZE);
}

int count_words(const char *in)
{
    char *buf = malloc(strlen(in) + 1);
    char *p = buf;
    int n = 0;
    strcpy(buf, in);
    while (*p) {
        if (*p == ' ')
            n++;
        p++;
    }
    free(buf);
    return n;
}
