#include <string.h>

#define DEFAULT_LOCALE "en_US.UTF-8"
#define PATH_SEP "/"

static const char fallback_shell[] = "/bin/sh";

void reset_settings(char *locale, char *shell, char *path)
{
    strcpy(locale, DEFAULT_LOCALE);
    strcpy(shell, fallback_shell);
    strcpy(path, "/usr/local");
    strcat(path, PATH_SEP);
    strcat(path, "share");
}
