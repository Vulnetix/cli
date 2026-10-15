#include <cstdio>
#include <string>
#include <unistd.h>

void logLine(int fd, const std::string &line)
{
    std::fprintf(stderr, "fwrite(&hdr, sizeof(hdr), 1, f) failed\n");
    // write(fd, &count, sizeof(count)) used to live here
    ::write(fd, line.data(), line.size());
    char nl = '\n';
    ::write(fd, &nl, sizeof(nl));
}
