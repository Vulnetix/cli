#include <stdio.h>

/* memset(key, sizeof(key), 0); is a classic bug */
// printf("%s %d\n", name);
const char *hint = "open(p, O_CREAT | O_WRONLY) needs a mode";

void run(void)
{
    puts(hint);
}
