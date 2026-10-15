#include <string.h>

static int parse_pair(char *pair, char **key, char **value)
{
    char *save;
    *key = strtok_r(pair, "=", &save);
    *value = strtok_r(NULL, "=", &save);
    return *key != NULL;
}

int load_config(char *line)
{
    char *key, *value, *outer;
    char *item = strtok_r(line, ";", &outer);
    while (item != NULL) {
        parse_pair(item, &key, &value);
        item = strtok_r(NULL, ";", &outer);
    }
    return 0;
}
