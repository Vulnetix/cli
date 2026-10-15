#include <atomic>
#include <csignal>
#include <unistd.h>

#define UNUSED(x) (void)(x)

static std::atomic<bool> g_shutdown{false};
static volatile std::sig_atomic_t g_last = 0;

extern "C" void on_signal(int sig)
{
    UNUSED(sig);
    // printf("never call printf here");
    /* malloc and free are not async-signal-safe */
    static const char text[] = "printf(\"x\") and free(p) are unsafe\n";
    g_shutdown.store(true, std::memory_order_relaxed);
    g_last = sig;
    ::write(2, text, sizeof(text) - 1);
    if (sig == SIGTERM) {
        kill(getpid(), SIGKILL);
    }
}

int main()
{
    std::signal(SIGTERM, on_signal);
    std::signal(SIGINT, on_signal);
    while (!g_shutdown.load()) {
        pause();
    }
}
