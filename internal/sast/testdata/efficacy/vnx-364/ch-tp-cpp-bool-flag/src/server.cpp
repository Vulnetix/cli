#include <csignal>
#include <string>

bool g_running = true;
std::string g_status;

void on_term(int)
{
~>	g_running = false;
~>	g_status = "stopping";
}

int main()
{
	std::signal(SIGTERM, on_term);
	while (g_running) {
	}
	return 0;
}
