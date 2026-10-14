#include <stdio.h>

struct entry {
    char key[32];
    int value;
};

int read_entries(FILE *fp, struct entry *e)
{
    char name[40];
    char word[16];
    int n;

    printf("name: ");
~>    scanf("%s", name);
~>    if (fscanf(fp, "%s %d", word, &n) != 2)
        return -1;
~>    return sscanf(name, "%[^=]=%d", e->key, &e->value);
}
