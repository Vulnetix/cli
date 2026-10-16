#include <stdio.h>
#include <string.h>

static void parse_pair(char *pair, char **key, char **value)
{
    *key = strtok(pair, "=");
    *value = strtok(NULL, "=");
}

int load(char *line)
{
    char *key, *value;
    char *item = strtok(line, ";");
    while (item != NULL) {
~>        parse_pair(item, &key, &value);
        printf("%s -> %s\n", key, value);
        item = strtok(NULL, ";");
    }
    return 0;
}
