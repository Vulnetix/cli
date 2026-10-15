#include <unistd.h>
#include <string.h>

int exe_path(char *out, size_t cap)
{
    ssize_t len;
    len = readlink("/proc/self/exe", out, cap - 1);
~>    out[len] = '\0';
    size_t slen = strlen(out);
~>    while (out[slen - 1] == '/')
        out[--slen] = 0;
    return 0;
}
