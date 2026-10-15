#include <cstdio>

bool append_log(const char *path, const char *msg)
{
    FILE *fp = fopen(path, "a");
    if (fp == nullptr) {
        return false;
    }
    fputs(msg, fp);
    fclose(fp);
    return true;
}
