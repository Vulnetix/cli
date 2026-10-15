#include <stdlib.h>
#include <unistd.h>

void lower(uid_t uid)
{
    seteuid(uid);
}

int run(const char *cmd)
{
    /* seteuid(uid); system(cmd); is unsafe */
    return system(cmd);
}
