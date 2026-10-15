#include <csignal>
#include <atomic>

static volatile std::sig_atomic_t g_quit = 0;
static std::atomic<int> g_hups{0};
static int g_reloads = 0;

int main() {
    std::signal(SIGINT, [](int) { g_quit = 1; });
    std::signal(SIGHUP, [](int sig) {
        int g_reloads = sig;
        g_hups++;
        (void)g_reloads;
    });
    while (!g_quit) {
        g_reloads++;
    }
    return 0;
}
