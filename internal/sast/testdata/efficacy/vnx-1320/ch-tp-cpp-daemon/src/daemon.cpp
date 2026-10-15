#include <csignal>
#include <iostream>

namespace svc {

void Daemon::installSignals() {
    std::signal(SIGPIPE, SIG_IGN);
~>    std::signal(SIGFPE, SIG_IGN);
    struct sigaction sa{};
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
~>    ::sigaction(SIGBUS, &sa, nullptr);
}

}  // namespace svc
