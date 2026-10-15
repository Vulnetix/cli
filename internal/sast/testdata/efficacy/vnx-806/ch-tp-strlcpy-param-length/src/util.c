#include <string.h>
#include <wchar.h>

void set_label(char *label, const char *text)
{
~>    strlcpy(label, text, strlen(text) + 1);
}

void set_wlabel(wchar_t *label, const wchar_t *text)
{
    size_t n = wcslen(text);
~>    wmemcpy(label, text, n);
}
