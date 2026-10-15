#include <string.h>
#include <stdlib.h>

void home(char *buf, int have)
{
    if (have)
~>        strcpy(buf, getenv("HOME"));
~>    (void)strcat(buf, argv_path);
}
