#include <stdio.h>

int file_size(FILE *fp)
{
    fseek(fp, 0, SEEK_END);
~>    int pos = ftell(fp);
    return pos;
}
