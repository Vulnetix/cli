#include <csignal>

namespace {
volatile std::sig_atomic_t g_term = 0;
void handle_term(int) { g_term = 1; }
}

void install_handlers()
{
~>    std::signal(SIGTERM, handle_term);
}
