#include <csignal>
#include <vector>

static std::vector<int> pending_jobs;
static int shutdown_requested = 0;

int run_worker()
{
	std::signal(SIGINT, [](int) {
~>		shutdown_requested = 1;
	});
	while (!shutdown_requested) {
		pending_jobs.push_back(1);
	}
	return 0;
}
