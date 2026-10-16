#include <csignal>
#include <cstdio>
#include <iostream>

static FILE *logf_;

static void cleanup()
{
    fclose(logf_);
}

extern "C" void on_usr1(int)
{
~>    cleanup();
~>    std::cout << "bye" << std::endl;
}

int main()
{
    std::signal(SIGUSR1, on_usr1);
    return 0;
}
