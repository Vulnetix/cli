#include <cerrno>

int Poller::wait_ready(int fd) {
    int rc;
again: // re-poll after a signal
    rc = ::poll(&pfd_, 1, timeout_ms_);
    if (rc < 0 && errno == EINTR)
~>        goto again;
    return rc;
}
