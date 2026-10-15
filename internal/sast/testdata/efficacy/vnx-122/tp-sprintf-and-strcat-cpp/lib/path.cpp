#include <cstdio>
#include <cstring>

char *make_path(const char *dir, const char *file)
{
    char *p = new char[256];
~>    sprintf(p, "%s/%s", dir, file);
    return p;
}

char *dup_label(const char *label)
{
~>    char *copy = new char[strlen(label)];
    strcpy(copy, label);
    return copy;
}
