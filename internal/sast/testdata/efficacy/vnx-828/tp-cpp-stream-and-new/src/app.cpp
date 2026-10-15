#include <csignal>
#include <iostream>
#include <string>

struct Snapshot {
    explicit Snapshot(int s) : sig(s) {}
    int sig;
};

static Snapshot *pending = nullptr;

void on_interrupt(int sig)
{
~>    std::cout << "interrupted by " << sig << std::endl;
~>    pending = new Snapshot(sig);
~>    std::string name = std::to_string(sig);
}

int main()
{
    std::signal(SIGINT, &on_interrupt);
    return 0;
}
