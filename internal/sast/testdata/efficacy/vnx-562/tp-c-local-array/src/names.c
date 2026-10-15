#include <stdio.h>
#include <string.h>

char *format_name(const char *first, const char *last)
{
    char buf[128];
    snprintf(buf, sizeof(buf), "%s %s", first, last);
~>    return buf;
}

const char *
greeting(int hour) {
    char msg[32], tmp[8];
    strcpy(msg, hour < 12 ? "morning" : "evening");
~>    return (msg);
}

char *first_char(void) {
    char word[16] = "hello";
~>    return &word[0];
}
