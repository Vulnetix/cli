#include <stdexcept>
#include <string>
#include <unistd.h>

#include "sandbox.h"

void Sandbox::enter(const std::string &root)
{
~>    if (::chroot(root.c_str()) != 0 || ::chdir("/") != 0)
        throw std::runtime_error("cannot enter " + root);
    spawnWorkers();
}
