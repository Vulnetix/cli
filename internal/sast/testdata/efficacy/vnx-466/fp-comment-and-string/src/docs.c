#include <stdio.h>
#include <string.h>

/* Never write: return strchr(s, '=') + 1; it returns NULL + 1 on a miss. */
// return strrchr(path, '/') + 1;
void explain(void)
{
    puts("return strchr(s, '=') + 1; is wrong when '=' is absent");
}
