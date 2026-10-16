#include <cstdio>
#include <fstream>

void trace(const char *msg)
{
    FILE *f = std::fopen("/tmp/trace.log", "a+");
    if (!f) return;
    std::fputs(msg, f);
    std::fclose(f);
}

void report()
{
~>    std::ofstream out("/dev/shm/report.txt", std::ios::trunc);
    out << "done\n";
}
