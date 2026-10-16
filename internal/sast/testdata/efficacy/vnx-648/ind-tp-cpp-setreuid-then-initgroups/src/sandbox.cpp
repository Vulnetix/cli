#include <grp.h>
#include <pwd.h>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace sandbox {

void enter(const std::string &account)
{
    struct passwd *pw = getpwnam(account.c_str());
    if (!pw) {
        throw std::runtime_error("unknown account " + account);
    }
~>    if (setreuid(pw->pw_uid, pw->pw_uid) != 0) {
        throw std::runtime_error("setreuid failed");
    }
    if (initgroups(pw->pw_name, pw->pw_gid) != 0) {
        throw std::runtime_error("initgroups failed");
    }
}

}  // namespace sandbox
