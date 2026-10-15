#include <stdio.h>
#include <string.h>

static int parse_pair(char *pair, char **key, char **value)
{
    *key = strtok(pair, "=");
    *value = strtok(NULL, "=");
    return *key != NULL && *value != NULL;
}

int load_config(char *line)
{
    char *key, *value;
    char *item = strtok(line, ";");
    while (item != NULL) {
~>        if (!parse_pair(item, &key, &value)) {
            fprintf(stderr, "bad pair\n");
        }
        item = strtok(NULL, ";");
    }
    return 0;
}
