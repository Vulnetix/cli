#include <stdlib.h>

static char g_name[64];
char g_buf[128] = {0};

void clear(void)
{
~>    free(g_name);
~>    free(g_buf);
~>    free("default");
}
