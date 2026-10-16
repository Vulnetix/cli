#include <csignal>
#include <iostream>
#include <cstring>

static void on_terminate(int sig, siginfo_t *info, void *)
{
    std::cerr << "terminating on signal " << sig << " from pid " << info->si_pid << std::endl;
    Server::instance().stop();
}

void InstallShutdownHandler()
{
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_terminate;
~>    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT, &sa, nullptr);
}
