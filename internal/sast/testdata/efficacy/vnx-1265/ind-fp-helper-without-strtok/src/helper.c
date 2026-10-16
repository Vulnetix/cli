#include <string.h>
#include <ctype.h>

static void trim(char *s)
{
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1])) s[--n] = 0;
}

void each(char *line)
{
    char *item = strtok(line, ";");
    while (item != NULL) {
        trim(item);
        /* strtok(item, "=") would corrupt the outer walk */
        item = strtok(NULL, ";");
    }
}
