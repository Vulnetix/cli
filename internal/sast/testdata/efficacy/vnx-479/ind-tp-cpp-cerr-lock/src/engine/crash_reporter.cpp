#include <csignal>
#include <iostream>
#include <mutex>
#include <unistd.h>

static std::mutex g_report_mu;

void abort_handler(int sig)
{
~>    std::lock_guard<std::mutex> lk(g_report_mu);
~>    std::cerr << "aborted with signal " << sig << std::endl;
    _exit(134);
}

void CrashReporter::install()
{
    std::signal(SIGABRT, abort_handler);
}
