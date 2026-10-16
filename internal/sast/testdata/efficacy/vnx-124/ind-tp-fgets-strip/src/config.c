#include <stdio.h>
#include <string.h>

int load_config(FILE *fp)
{
    char line[512];
    while (fgets(line, sizeof(line), fp) != NULL) {
~>        line[strlen(line) - 1] = '\0';
        apply_setting(line);
    }
    return 0;
}
