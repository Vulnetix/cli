#include <unistd.h>

int copy_all(int in, int out, char *buf, size_t sz)
{
    size_t n;
    for (;;) {
        n = read(in, buf, sz);
~>        if (n < 0)
            return -1;
        if (n == 0)
            break;
        write(out, buf, n);
    }
    return 0;
}
