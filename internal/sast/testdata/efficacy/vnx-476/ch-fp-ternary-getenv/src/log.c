#include <stdio.h>
#include <stdlib.h>

void print_level(void)
{
    const char *level = getenv("LOG_LEVEL");
    printf("level=%s\n", level ? level : "info");
    const char *dir = getenv("TMPDIR");
    if (!dir)
        dir = "/tmp";
    printf("%s\n", dir);
}
