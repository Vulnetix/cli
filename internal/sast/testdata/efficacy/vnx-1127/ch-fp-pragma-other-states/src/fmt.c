#include <stdio.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wformat-security"
#pragma GCC diagnostic warning "-Wall"
#pragma GCC diagnostic ignored "-Wformat-truncation"
_Pragma("GCC diagnostic ignored \"-Wunused-parameter\"")
#pragma GCC diagnostic pop

static const char *help = "_Pragma(\"GCC diagnostic ignored \\\"-Wformat\\\"\")";

int show(const char *name) {
    return printf("%s\n", name);
}
