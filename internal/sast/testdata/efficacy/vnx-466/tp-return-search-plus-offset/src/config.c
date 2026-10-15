#include <string.h>

/* Returns the value part of a "key=value" entry. */
const char *config_value(const char *entry)
{
~>    return strchr(entry, '=') + 1;
}

char *after_last_colon(char *s) {
~>	return strrchr( s , ':' )+1;
}

const char *skip_prefix(const char *s)
{
~>    return (const char *)memchr(s, ' ', strlen(s)) + 1;
}
