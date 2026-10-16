#include <csignal>
#include <iostream>
#include <vector>

std::vector<int> *pending;

extern "C" void on_usr1(int)
{
    std::cout << "dumping state" << std::endl;
    pending = new std::vector<int>();
}

int main()
{
    std::signal(SIGUSR1, on_usr1);
    return 0;
}
