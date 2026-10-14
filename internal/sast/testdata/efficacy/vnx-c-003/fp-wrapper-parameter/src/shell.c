#include <stdlib.h>

/* The caller decides the command; the construction is reviewed there. */
int run_command(const char *command)
{
    return system(command);
}

FILE *open_pipe(const char *command)
{
    return popen(command, "r");
}
