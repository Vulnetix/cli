#include <stdio.h>

void read_input(FILE *f, const char *src)
{
    char word[16];
    char rest[64];
~>    scanf("%s", word);
~>    fscanf(f, "%d %s", &n, word);
~>    sscanf(src, "%[^\n]", rest);
}
