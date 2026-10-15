#include <string.h>
#include <stdlib.h>

void reset(struct ctx *c) {
    memset(c->key, 0, sizeof(c->key));
    return;
}

void clear_buffer(void) {
    char line[256];
    read_line(line);
    memset(line, 0, sizeof line);
    free(other);
}

void clear_param(char *password) {
    memset(password, 0, 64);
    return;
}

void zoo(void) {
    char *monkey = malloc(16);
    fill(monkey);
    memset(monkey, 0, 16);
    free(monkey);
}
