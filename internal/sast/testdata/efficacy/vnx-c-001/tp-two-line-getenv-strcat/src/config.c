#include <stdlib.h>
#include <string.h>

#define CONFIG_NAME "/.toolrc"

static char config_path[256];

const char *config_file(void)
{
    const char *home = getenv("HOME");

    if (home == NULL)
        return NULL;
    config_path[0] = '\0';
~>    strcat(config_path, home);
    strcat(config_path, CONFIG_NAME);
    return config_path;
}

void set_label(char *dst, const char *label)
{
~>    stpcpy(dst, label);
}
