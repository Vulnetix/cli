#include <stdio.h>
#include <string.h>

int main(void)
{
    char line[128];
    for (;;) {
        fputs("> ", stdout);
~>        if (gets(line) == NULL)
            break;
        if (strcmp(line, "quit") == 0)
            break;
        printf("echo: %s\n", line);
    }
    return 0;
}
