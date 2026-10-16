#include <stdio.h>

void read_line(FILE *fp)
{
    char buf[0x100];
    if (fgets(buf, 256, fp))
        consume(buf);
}
