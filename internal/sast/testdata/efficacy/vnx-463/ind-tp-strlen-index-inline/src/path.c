#include <stdio.h>
#include <string.h>

void print_dir(char *buf)
{
~>    buf[strlen(buf)] = '/';
    puts(buf);
}
