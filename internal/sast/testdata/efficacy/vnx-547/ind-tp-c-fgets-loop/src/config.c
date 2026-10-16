#include <stdio.h>
#include <string.h>

int load_config(const char *path)
{
    FILE *fp = fopen(path, "r");
    char buf[128];

    if (fp == NULL)
        return -1;
~>    while (fgets(buf, 128, fp) != NULL) {
        buf[strcspn(buf, "\n")] = '\0';
        apply_line(buf);
    }
    fclose(fp);
    return 0;
}
