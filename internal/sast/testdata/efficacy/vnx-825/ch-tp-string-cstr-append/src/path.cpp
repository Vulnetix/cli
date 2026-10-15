#include <cstdio>
#include <string>

void log_path(const std::string &dir, const std::string &file)
{
    std::string full = dir;
    const char *view = full.c_str();
    full += "/";
    full.append(file);
~>    std::puts(view);
}

void bump(std::vector<int> &scores)
{
    int *first = &scores[0];
    scores.resize(scores.size() * 2);
~>    first[0] += 1;
}
