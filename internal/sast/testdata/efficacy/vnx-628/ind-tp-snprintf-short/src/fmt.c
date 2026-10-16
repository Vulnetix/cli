#include <stdio.h>

void fmt_line(char *buf, size_t n, const char *tag, int level, double t)
{
~>    snprintf(buf, n, "[%s] level=%d t=%.3f", tag, level);
    (void)t;
}
