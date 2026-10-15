#include <stdlib.h>
#include <string.h>

char *dup(const char *s)
{
    char *d = malloc(strlen(s) + 1);
    memcpy(d, s, strlen(s) + 1);
    char buf[64];
    strncpy(buf, s, sizeof(buf) - 1);
    snprintf(buf, sizeof buf, "%s", s);
    return d;
}

size_t wide_len(const wchar_t *w)
{
    const char *narrow = "abc";
    return wcslen(w) + strlen(narrow);
}
