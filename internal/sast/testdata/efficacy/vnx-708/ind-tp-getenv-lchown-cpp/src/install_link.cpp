#include <cstdlib>
#include <iostream>
#include <string>
#include <unistd.h>

namespace installer {

bool fix_link_owner(uid_t uid, gid_t gid)
{
    const char *link_path = std::getenv("INSTALL_LINK");
    if (link_path == nullptr) {
        std::cerr << "INSTALL_LINK not set\n";
        return false;
    }
~>    if (::lchown(link_path, uid, gid) == -1) {
        std::perror("lchown");
        return false;
    }
    return true;
}

}  // namespace installer
