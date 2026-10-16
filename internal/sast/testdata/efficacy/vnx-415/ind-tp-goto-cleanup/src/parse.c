#include <stdlib.h>
#include <string.h>

int parse_entry(const char *line, struct entry *out)
{
    int rc = -1;
    char *key = strdup(line);
    char *value = NULL;

    if (key == NULL)
        return -1;
    value = strchr(key, '=') ? strdup(strchr(key, '=') + 1) : NULL;
    if (value == NULL) {
~>        free(key);
        goto fail;
    }
    out->key = key;
    out->value = value;
    return 0;

fail:
    free(value);
    free(key);
    return rc;
}
