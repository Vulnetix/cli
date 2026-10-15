#include <fcntl.h>
#include <unistd.h>

int copy_file(const char *src, const char *dst)
{
    char buf[4096];
    ssize_t n;
    int in = open(src, O_RDONLY);
    int out = open(dst, O_WRONLY | O_CREAT, 0644);
    while ((n = read(in, buf, sizeof buf)) > 0)
        write(out, buf, n);
    close(in);
    close(out);
    if (n < 0) {
~>        close(in);
        return -1;
    }
    return 0;
}
