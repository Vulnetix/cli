#include <grp.h>
#include <tuple>
#include <unistd.h>

#include "worker.h"

void Worker::demote()
{
~>    std::ignore = ::setgroups(0, nullptr);
~>    (void)!setgid(gid_);
~>    static_cast<void>(setuid(uid_));
    run();
}
