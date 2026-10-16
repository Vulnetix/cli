#include <unistd.h>

void lower(uid_t uid)
{
    ::seteuid(uid);
}

void start(char *const argv[])
{
    ::execv(argv[0], argv);
}
