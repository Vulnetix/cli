#include <stdio.h>
#include <stdlib.h>
#include <string.h>

FILE *open_spool(void)
{
    char name[L_tmpnam];
~>    if (tmpnam(name) == NULL)
        return NULL;
    return fopen(name, "w+");
}

int make_scratch(char *out, size_t n)
{
    char tmpl[] = "/tmp/spoolXXXXXX";
~>    char *p = mktemp(tmpl);
    if (p == NULL || *p == '\0')
        return -1;
    strncpy(out, p, n);
    return 0;
}

char *name_only(void)
{
~>    return tmpnam (NULL);
}
