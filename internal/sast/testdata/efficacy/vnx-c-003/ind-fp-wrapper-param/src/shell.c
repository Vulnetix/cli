#include <stdio.h>
#include <stdlib.h>

int run_shell(const char *command);

int run_shell(const char *command)
{
    int rc = system(command);
    if (rc != 0)
        fprintf(stderr, "command failed: %d\n", rc);
    return rc;
}

FILE *open_pipe(const char *command, const char *mode)
{
    return popen(command, mode);
}
