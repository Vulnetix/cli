#include <stdio.h>
#include <string.h>

void log_path(const char *dir, const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    printf("%s\n", path);
    char line[256];
    while (fgets(line, sizeof line, stdin) != NULL)
        puts(line);
}
