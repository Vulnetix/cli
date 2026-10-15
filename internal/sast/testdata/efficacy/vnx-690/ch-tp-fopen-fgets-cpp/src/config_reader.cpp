#include <cstdio>
#include <string>

std::string first_line(const char *path)
{
    char line[256];
    FILE *fp = std::fopen(path, "r");
~>    std::fgets(line, sizeof line, fp);
    std::fclose(fp);
    return std::string(line);
}
