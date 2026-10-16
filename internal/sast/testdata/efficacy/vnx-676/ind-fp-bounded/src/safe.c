#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void safe(const char *user, FILE *in) {
    char line[64];
    char name[32];
    char word[16];
    char out[40];
    fgets(line, sizeof line, in);
    strncpy(name, user, sizeof name - 1);
    snprintf(out, sizeof out, "hello %s", user);
    sscanf(line, "%15s", word);
    sprintf(out, "%.20s", user);
    sprintf(out, "%d-%d", 1, 2);
    scanf("%31s", word);
}
