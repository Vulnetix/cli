#include <cstring>

void chomp(char *line)
{
    std::size_t n = std::strlen(line);
    if (n > 0 && line[n - 1] == '\n')
        line[n - 1] = '\0';
    line[std::strlen(line)] = '\0';
}
