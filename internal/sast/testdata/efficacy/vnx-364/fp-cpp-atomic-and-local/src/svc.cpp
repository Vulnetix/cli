#include <atomic>
#include <csignal>

std::atomic<bool> stopRequested{false};
_Atomic int pending;
int config_version = 3;

extern "C" void handler(int sig)
{
    int local = sig;
    local++;
    stopRequested = true;
    pending = 1;
}

int main()
{
    std::signal(SIGINT, handler);
    config_version = 4;
    return config_version;
}
