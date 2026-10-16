#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char *slurp(const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
~>    int size = ftell(fp);
    rewind(fp);
    char *buf = malloc(size + 1);
    fread(buf, 1, size, fp);
    buf[size] = '\0';
    fclose(fp);
    return buf;
}

int tail_offset(FILE *fp)
{
    int pos;
~>    pos = (int)ftello(fp);
    return pos;
}
