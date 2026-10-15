#include <csignal>
#include <cstdlib>

static void onFault(int sig) {
    std::_Exit(128 + sig);
}

void Server::init() {
    std::signal(SIGPIPE, SIG_IGN);
    std::signal(SIGSEGV, onFault);
    std::signal(SIGABRT, SIG_DFL);
    // std::signal(SIGSEGV, SIG_IGN);  never do this
    log("signal(SIGFPE, SIG_IGN) is forbidden here");
}
