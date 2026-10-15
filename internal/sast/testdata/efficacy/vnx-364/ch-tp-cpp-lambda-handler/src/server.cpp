#include <csignal>
#include <cstdio>

static bool g_stop = false;
static int g_signals = 0;

int main() {
    std::signal(SIGTERM, [](int) {
~>        g_stop = true;
~>        g_signals++;
    });
~>    std::signal(SIGUSR1, [](int) { g_signals = 0; });
    while (!g_stop) {
        std::puts("tick");
    }
    return g_signals;
}
