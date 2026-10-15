#include <stdint.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>

void wake(int efd)
{
    uint64_t one = 1;
    write(efd, &one, sizeof(one));
}

void drain(int wakeup_pipe[2], int sfd)
{
    uint64_t v;
    read(wakeup_pipe[0], &v, sizeof v);
    struct signalfd_siginfo si;
    read(sfd, &si, sizeof(si));
}
