#include <stdio.h>
#include <string.h>

struct user {
    char name[32];
    char home[64];
};

void set_name(struct user *u, const char *input)
{
~>    strncpy(u->name, input, sizeof(u->name));
    printf("hello %s\n", u->name);
}

void set_home(struct user *u, const char *dir)
{
    char tmp[64];
~>    strncpy( tmp,
             dir, sizeof tmp );
    strcpy(u->home, tmp);
}
