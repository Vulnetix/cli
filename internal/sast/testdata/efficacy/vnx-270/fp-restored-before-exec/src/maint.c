#include <unistd.h>
#include <stdlib.h>

int rotate(uid_t uid)
{
    seteuid(uid);
    write_user_report();
    seteuid(0);
    return system("/usr/sbin/logrotate /etc/logrotate.conf");
}
