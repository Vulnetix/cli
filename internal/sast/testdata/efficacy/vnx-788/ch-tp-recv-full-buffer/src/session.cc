#include <unistd.h>

int Session::readLine()
{
    char line[256];
    ssize_t got = ::read(fd_, line, sizeof line);
    if (got <= 0)
        return -1;
~>    line[got] = '\0';
    return dispatch(line);
}
