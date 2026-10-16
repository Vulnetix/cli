#include <stdlib.h>
#include <string.h>

int home_path(char *dst, size_t cap)
{
    const char *home = getenv("HOME");
    if (!home)
        home = "/tmp";
    strncpy(dst, home, cap - 1);
    dst[cap - 1] = '\0';
    return 0;
}
