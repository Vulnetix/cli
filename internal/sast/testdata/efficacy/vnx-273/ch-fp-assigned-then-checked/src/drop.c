#include <stdlib.h>
#include <unistd.h>

void drop(uid_t uid, gid_t gid)
{
    int rc = setgid(gid);
    if (rc != 0)
        abort();
    rc = setuid(uid);
    if (rc != 0)
        abort();
}
