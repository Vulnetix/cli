#include <stdio.h>
#include <string.h>

int login(const char *user)
{
    char name[32];
    char line[128];
~>    gets(line);
~>    strcpy(name, user);
    return check(name, line);
}
