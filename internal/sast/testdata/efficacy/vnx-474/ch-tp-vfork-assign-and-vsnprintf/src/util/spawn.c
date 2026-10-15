#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

int spawn(char *const argv[])
{
    pid_t pid;
~>    if ((pid = vfork()) == 0) {
        execv(argv[0], argv);
        _exit(127);
    }
    return pid;
}

void log_line(char *buf, size_t n, const char *fmt, va_list ap)
{
~>    _vsnprintf(buf, n, fmt, ap);
}
