#include <csignal>
#include <iostream>

namespace {
Session *current = nullptr;
}

void handle_stop(int signum)
{
    std::cerr << "stopping on " << signum << std::endl;
    delete current;
    current = nullptr;
}

int run()
{
~>    std::signal(SIGINT, handle_stop);
~>    std::signal(SIGQUIT, handle_stop);
    current = new Session();
    return current->loop();
}
