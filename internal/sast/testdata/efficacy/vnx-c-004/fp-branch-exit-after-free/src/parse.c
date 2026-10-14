#include <stdlib.h>

int parse(char *buf, size_t len)
{
    if (len == 0) {
        free(buf);
        return -1;
    }
    if (buf[0] == '#') {
        free(buf);
        goto out;
    }
    switch (buf[1]) {
    case 'a':
        free(buf);
        break;
    case 'b':
        buf[0] = 'c';
        break;
    }
    for (;;) {
        if (len > 4) {
            free(buf);
            buf = NULL;
        }
        if (buf)
            buf[2] = 0;
        break;
    }
    if (len > 10)
        free(buf);
    else
        buf[0] = 0;
out:
    return 0;
}
