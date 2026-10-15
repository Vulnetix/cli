#include <stdio.h>
#include <string.h>

void parse_pairs(char *text)
{
    char *outer = NULL;
    char *pair = strtok(text, "&");
    while (pair != NULL) {
        char *inner = NULL;
        char *key = strtok_r(pair, "=", &inner);
        char *val = strtok_r(NULL, "=", &inner);
        printf("%s=%s\n", key, val ? val : "");
        pair = strtok(NULL, "&");
    }
    (void)outer;
}
