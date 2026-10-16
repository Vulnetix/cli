#include <stdio.h>

/* Bad: uint16_t len = strlen(name); truncates long names. */
void warn(void)
{
    // int size = ftell(fp);  -- use long instead
    puts("do not write: int size = ftell(fp);");
}
