#include <atomic>
#include <csignal>

static std::atomic<bool> g_running{true};
static std::atomic<int> g_signals{0};

extern "C" void handle_stop(int)
{
	g_running = false;
	g_signals++;
}

int serve()
{
	std::signal(SIGTERM, handle_stop);
	std::signal(SIGINT, handle_stop);
	while (g_running) {
	}
	return 0;
}
