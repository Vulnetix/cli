#include <unistd.h>

void drop_privileges(uid_t uid, gid_t gid)
{
~>    setgid(gid);
~>    setuid(uid);
    run_untrusted();
}
