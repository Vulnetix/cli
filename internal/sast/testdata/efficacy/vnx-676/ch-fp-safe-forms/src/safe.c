#include <stdio.h>
#include <string.h>

void safe(char *dst, size_t dstsz, const char *src, char *word)
{
    snprintf(dst, dstsz, "%s", src);
    sprintf(dst, "%d-%u", 1, 2u);
    sprintf(dst, "%.31s", src);
    sscanf(src, "%31s", word);
    strcpy(dst, DEFAULT_NAME);
    strcpy(dst, flag ? "on" : "off");
    strncpy(dst, src, dstsz - 1);
    char *end = stpcpy(dst, "x");
}
