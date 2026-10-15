#include <stdio.h>
#include <stdlib.h>

FILE *audit;

void init_audit(const char *path)
{
~>    audit = fopen(path, "a");
}

void notify(const char *cmd)
{
    system(cmd);
}
