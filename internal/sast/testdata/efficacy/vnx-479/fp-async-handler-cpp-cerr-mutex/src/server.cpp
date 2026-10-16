#include <csignal>
#include <iostream>
#include <mutex>

static std::mutex state_lock;

extern "C" void on_interrupt(int)
{
    std::lock_guard<std::mutex> guard(state_lock);
    std::cerr << "interrupted" << std::endl;
}

int main()
{
    std::signal(SIGINT, on_interrupt);
    return run();
}
