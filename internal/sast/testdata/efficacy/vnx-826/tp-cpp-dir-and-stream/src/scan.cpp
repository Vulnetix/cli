#include <cstdio>
#include <dirent.h>
#include <string>
#include <vector>

std::vector<std::string> list_entries(const char *root)
{
    std::vector<std::string> out;
    DIR *dir = opendir(root);
    if (!dir) {
        return out;
    }
~>    closedir(dir);
    while (struct dirent *ent = readdir(dir)) {
        out.emplace_back(ent->d_name);
    }
    return out;
}

void flush_log(std::FILE *log, const std::string &line)
{
    std::fputs(line.c_str(), log);
~>    std::fclose(log);
    std::fflush(log);
}
