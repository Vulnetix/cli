#include <cstdio>
#include <spawn.h>

extern char **environ;

bool Runner::init(const std::string &log)
{
~>    log_ = std::fopen(log.c_str(), "a");
    return log_ != nullptr;
}

int Runner::launch(char *const argv[])
{
    pid_t pid;
    return posix_spawn(&pid, argv[0], nullptr, nullptr, argv, environ);
}
