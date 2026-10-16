#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

void dump_report(int code)
{
    char *buf = malloc(256);
    snprintf(buf, 256, "exit code %d\n", code);
    fputs(buf, stderr);
    free(buf);
}

void install(void)
{
    signal(SIGSEGV, SIG_DFL);
}
