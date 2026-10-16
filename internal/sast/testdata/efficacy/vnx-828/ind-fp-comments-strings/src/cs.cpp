#include <csignal>
#include <atomic>
#include <cstdio>

static std::atomic<bool> stop{false};

void on_quit(int)
{
    // printf("quitting\n"); exit(0);
    const char *s = "printf(\"x\"); free(p);";
    (void)s;
    stop.store(true);
}

int main()
{
    std::signal(SIGQUIT, on_quit);
    return 0;
}
