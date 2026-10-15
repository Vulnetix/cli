#include <stdio.h>

/* int total;
 * total += v[i];   reads an uninitialized local */
// char msg[128]; strcat(msg, who);
const char *kExample = "int n; n++;";

void doc(void)
{
    puts(kExample);
}
