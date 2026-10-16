#include <limits.h>
#include <unistd.h>

const char *self_exe(void)
{
    static char target[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", target, sizeof(target) - 1);
~>    target[len] = '\0';
    return target;
}
