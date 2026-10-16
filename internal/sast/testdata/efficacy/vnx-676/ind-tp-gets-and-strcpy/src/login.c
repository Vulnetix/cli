#include <stdio.h>
#include <string.h>

struct user {
    char name[32];
    char home[64];
};

void read_user(struct user *u, const char *home_from_env)
{
    char line[128];
    printf("username: ");
~>    gets(line);
~>    strcpy(u->name, line);
~>    strcat(u->home, home_from_env);
}
