#include <dirent.h>
#include <stdio.h>

void list(const char *path)
{
    DIR *d = opendir(path);
    struct dirent *e;
    if (!d) return;
~>    closedir(d);
    e = readdir(d);
    if (e) puts(e->d_name);
}
