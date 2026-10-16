#include <stdio.h>

void log_line(FILE *fp, const char *msg, const void *buf, size_t n)
{
~>    fputs(stderr, msg);
~>    fwrite(fp, buf, 1, n);
}

void read_line(FILE *stream, char *line, int size)
{
~>    fgets(stream, line, size);
}
