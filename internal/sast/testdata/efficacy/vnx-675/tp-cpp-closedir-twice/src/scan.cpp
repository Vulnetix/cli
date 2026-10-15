#include <dirent.h>

int count_entries(const char *dir)
{
    DIR *d = opendir(dir);
    int n = 0;
    while (readdir(d) != nullptr)
        ++n;
    closedir(d);
~>    closedir(d);
    return n;
}
