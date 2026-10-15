#include <string.h>

char *field_after(char *line)
{
    char *p = strchr(line, '\t');
    p = line + strlen(line);
    return p + 1;
}

/* return strchr(s, ',') + 1; would be wrong without a check */
const char *msg = "return strchr(s, ',') + 1;";
