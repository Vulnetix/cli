#include <grp.h>
#include <unistd.h>

#include "daemon.h"

void Daemon::dropPrivileges(uid_t uid, gid_t gid)
{
~>    ::setgroups(0, nullptr);
~>    ::setgid(gid);
~>    ::setuid(uid);
}
