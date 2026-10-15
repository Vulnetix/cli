#include <stdio.h>

void help(void)
{
    // int n = atoi(argv[1]); char *p = malloc(n); is unsafe
    puts("malloc(atoi(argv[1])) allocates whatever the user asks for");
}
