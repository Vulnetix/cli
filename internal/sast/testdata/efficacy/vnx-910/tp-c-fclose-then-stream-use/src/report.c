#include <stdio.h>

void finish(FILE *log, int rows)
{
    fflush(log);
    fclose(log);
~>    fprintf(log, "wrote %d rows\n", rows);
}

void dump(FILE *out, const char *buf, size_t n)
{
    if (n == 0) fclose(out);
~>    fwrite(buf, 1, n, out);
}
