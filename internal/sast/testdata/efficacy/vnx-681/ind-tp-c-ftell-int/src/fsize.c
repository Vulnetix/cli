#include <stdio.h>

long file_len(FILE *fp)
{
    fseek(fp, 0, SEEK_END);
~>    int size = ftell(fp);
    rewind(fp);
    return size;
}

void mark(FILE *fp, int *pos)
{
~>    *pos = (int)ftello(fp);
}
