#include <csignal>
#include <string>

bool g_stop = false;
std::string g_reason;

void onSignal(int sig)
{
~>    g_stop = true;
~>    g_reason = "signal";
}

int main()
{
    std::signal(SIGTERM, onSignal);
    while (!g_stop) {
    }
    return 0;
}
