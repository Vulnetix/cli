#include <string.h>

char *strcpy(char *dst, const char *src);
#define COPY(d, s) strcpy(d, s)

/* Never call gets(line); it cannot be bounded. */
static const char *msg = "strcpy(dst, src) is unsafe";

void my_strcpy(char *d, const char *s);

void copy(struct buf *b, char *d, const char *s)
{
    my_strcpy(d, s);
    b->gets(d);
}
