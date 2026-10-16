#include <stdio.h>
#include <stdlib.h>

int run_post_hook(void)
{
~>    return system(getenv("POST_DEPLOY_HOOK"));
}

int main(int argc, char *argv[])
{
    char line[1024];
    if (argc > 1)
~>        system(argv[1]);
    while (fgets(line, sizeof(line), stdin) != NULL)
~>        system(line);
    return run_post_hook();
}
