#include <csignal>
#include <exception>
#include <iostream>
#include <unistd.h>

void drop(uid_t uid, gid_t gid)
{
    if (::setgid(gid) != 0) {
        std::cerr << "setgid failed\n";
        std::terminate();
    }
    if (::setuid(uid) != 0) {
        std::cerr << "setuid failed\n";
        std::raise(SIGKILL);
    }
}
