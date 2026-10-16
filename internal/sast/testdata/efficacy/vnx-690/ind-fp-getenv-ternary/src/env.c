#include <stdlib.h>
#include <string.h>

void pick_home(char *dst)
{
    strcpy(dst, getenv("HOME") ? getenv("HOME") : "/");
    const char *lang = getenv("LANG");
    if (!lang)
        lang = "C";
    (void)strlen(lang);
}
