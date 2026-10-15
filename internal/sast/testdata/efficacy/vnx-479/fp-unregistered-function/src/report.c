#include <stdio.h>
#include <stdlib.h>

void report(int code)
{
    printf("exit code %d\n", code);
    exit(code);
}

void cleanup(int sig)
{
    free(NULL);
}
