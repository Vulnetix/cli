#include <stdio.h>
#include "log.h"

/* Wrong: printf("user %s failed with %d\n", user); never do this. */
void report(const char *user, int code)
{
    // memset(key, sizeof(key), 0) is the classic transposed-args bug
    my_printf("user %s failed with %d\n", user);
    LOG_WARN("user %s code %d", user);
    const char *doc = "printf(\"%s %d\", x) needs two arguments";
    puts(doc);
}
