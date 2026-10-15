#include <cstdint>
#include <cstdio>
#include <unistd.h>

void persist(std::FILE *f, int fd, std::uint64_t count, int value)
{
~>    std::fwrite(&count, sizeof(count), 1, f);
~>    ::write(fd, &value, sizeof(value));
}
