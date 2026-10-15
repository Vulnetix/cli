#include <string.h>
#include <stdio.h>

struct user { char name[32]; };

void swap_names(struct user *users, char names[][32], int i, int j)
{
    char tmp[32];
    strcpy(tmp, users[i].name);
    strcpy(users[i].name, users[j].name);
    strcpy(names[i], names[j]);
}

int needed(const char *s)
{
    int n = snprintf(NULL, 0, "%s", s);
    return n + 1;
}
