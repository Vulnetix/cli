#include <csignal>

void init() {
~>    std::signal(SIGFPE, SIG_IGN);
    std::signal(SIGTERM, on_term);
}
