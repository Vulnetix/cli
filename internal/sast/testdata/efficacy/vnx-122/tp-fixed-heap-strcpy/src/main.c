#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    char *buf = (char *)malloc(64);
    if (!buf)
        return 1;
~>    strcpy(buf, argv[1]);
    puts(buf);
    free(buf);
    return 0;
}

void greet(const char *who)
{
    char *line = malloc(BUF_LEN);
~>    gets(line);
~>    strcat(line, who);
    free(line);
}
