#include <stdio.h>
#include <string.h>

int load_config(FILE *fp)
{
    char line[512];
    while (fgets(line, sizeof(line), fp) != NULL) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';
        apply_setting(line);
    }
    return 0;
}
