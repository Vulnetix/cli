#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONFIG_DIR "/.config/acme"

static char config_path[256];

const char *resolve_config_path(void)
{
    const char *home = getenv("HOME");
    if (home == NULL) {
        return NULL;
    }
~>    strcpy(config_path, home);
    strcat(config_path, CONFIG_DIR);
    return config_path;
}

void append_profile(const char *profile)
{
    strcat(config_path, "/");
~>    strcat(config_path, profile);
}
