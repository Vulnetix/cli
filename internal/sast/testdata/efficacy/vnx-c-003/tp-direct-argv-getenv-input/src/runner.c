#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    char line[256];
    const char *editor = getenv("EDITOR");

    if (argc > 1)
~>        system(argv[1]);

    if (editor != NULL)
~>        system(editor);

    while (fgets(line, sizeof(line), stdin) != NULL) {
~>        system(line);
    }
~>    return system(getenv("POST_HOOK"));
}
