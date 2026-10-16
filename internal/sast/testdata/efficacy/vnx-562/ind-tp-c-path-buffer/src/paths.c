#include <limits.h>
#include <stdio.h>
#include <string.h>

const char *config_path(const char *home, const char *app)
{
    char path[PATH_MAX];

    if (snprintf(path, sizeof path, "%s/.config/%s/config.ini", home, app) >= (int)sizeof path) {
        return NULL;
    }
~>    return path;
}
