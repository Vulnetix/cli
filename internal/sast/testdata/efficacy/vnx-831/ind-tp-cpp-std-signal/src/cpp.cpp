#include <csignal>
#include <iostream>

static void quit(int s)
{
    std::cout << "signal " << s << std::endl;
}

int main()
{
~>    std::signal(SIGINT, quit);
~>    std::signal(SIGQUIT, quit);
    return 0;
}
