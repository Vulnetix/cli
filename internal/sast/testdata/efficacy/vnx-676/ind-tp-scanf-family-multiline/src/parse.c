#include <stdio.h>

int parse_record(const char *rec, FILE *in)
{
    char word[32];
    char key[16], val[64];
    int id;

~>    scanf("%s", word);
~>    if (sscanf(rec, "%d:%[^=]=%63s",
               &id, key, val) != 3)
        return -1;
~>    fscanf(in, "%s %d", word, &id);
    return id;
}
