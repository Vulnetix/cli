#include <string.h>

void build(char *path, const char *dir, const char *file) {
    char full[256];
    strcpy(full, dir);
~>    strncat(full, file, sizeof(full));
~>    strncat(full, "/", sizeof full);
~>    strncpy(path, file, strlen(file));
~>    strncat(s->name, suffix, strlen( suffix ));
}
