#include <stdio.h>
#include <string.h>

void read_name(const char *user) {
    char line[64];
    char name[32];
~>    gets(line);
~>    strcpy(name, user);
    printf("%s %s\n", line, name);
}
