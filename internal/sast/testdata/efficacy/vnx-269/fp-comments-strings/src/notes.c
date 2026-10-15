#include <stdio.h>
/* calling setuid(uid) before setgid(gid) leaves group root */
void f(uid_t uid, gid_t gid)
{
    printf("setuid(%d)\n", uid);
    printf("then setgid(%d)\n", gid);
}
