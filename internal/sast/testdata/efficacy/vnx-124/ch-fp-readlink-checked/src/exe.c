#include <unistd.h>

int self_path(char *target, size_t size)
{
    ssize_t n = readlink("/proc/self/exe", target, size - 1);
    if (n < 0)
        return -1;
    target[n] = '\0';
    return 0;
}
