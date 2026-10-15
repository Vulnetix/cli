#include <thread>
#include <unistd.h>

void serve();

int run(gid_t group)
{
    std::thread t(serve);
~>    ::setegid(0);
    int rc = chown("/run/svc.sock", 0, 0);
    ::setegid(group);
    t.join();
    return rc;
}
