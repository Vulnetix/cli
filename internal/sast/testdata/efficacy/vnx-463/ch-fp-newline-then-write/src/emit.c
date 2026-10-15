#include <string.h>
#include <unistd.h>

void emit_line(int fd, char *msg)
{
    size_t n = strlen(msg);
    msg[n] = '\n';
    write(fd, msg, n + 1);
}
