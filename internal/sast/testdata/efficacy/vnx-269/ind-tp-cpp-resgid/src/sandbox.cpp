#include <stdexcept>
#include <sys/types.h>
#include <unistd.h>

namespace sandbox {

void enter(uid_t uid, gid_t gid)
{
    if (::setresuid(uid, uid, uid) != 0)
        throw std::runtime_error("setresuid");
~>    if (::setresgid(gid, gid, gid) != 0)
        throw std::runtime_error("setresgid");
}

}  // namespace sandbox
