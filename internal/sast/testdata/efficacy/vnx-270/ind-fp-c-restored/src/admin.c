#include <stdlib.h>
#include <unistd.h>

int refresh(uid_t uid)
{
    if (seteuid(uid) != 0)
        return -1;
    read_user_config();
    if (seteuid(0) != 0)
        return -1;
    return system("/usr/sbin/update-ca-certificates");
}
