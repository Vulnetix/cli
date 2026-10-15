#include <stdio.h>

/* char *bad(void) { char buf[8]; return buf; } */
const char *hint(void)
{
    // char tmp[4]; return tmp;
    return "return buf; is undefined behaviour";
}
