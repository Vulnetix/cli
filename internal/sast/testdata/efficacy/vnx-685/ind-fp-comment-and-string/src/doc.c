#include <stdio.h>

/* printf("%s %d\n", user); reads garbage from the stack */
void explain(void)
{
    // open(path, O_CREAT | O_WRONLY);
    puts("open(path, O_CREAT) needs a mode");
}
