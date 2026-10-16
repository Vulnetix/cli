#include <stdio.h>
#include <string.h>

int main(void)
{
    char line[128];

    printf("> ");
~>    while (gets(line) != NULL) {
        if (strcmp(line, "quit") == 0)
            break;
        eval(line);
        printf("> ");
    }
    return 0;
}
