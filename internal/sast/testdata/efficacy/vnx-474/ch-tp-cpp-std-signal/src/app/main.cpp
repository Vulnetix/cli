#include <csignal>
#include <atomic>

static std::atomic<bool> stop{false};

static void on_term(int) { stop = true; }

int main()
{
~>    std::signal(SIGTERM, on_term);
    while (!stop) {
    }
    return 0;
}
