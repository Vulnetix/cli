#include <string.h>

/* Return the value part of a "key=value" line. */
const char *ini_value(const char *entry)
{
~>    return strchr(entry, '=') + 1;
}
