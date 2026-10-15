#include <string.h>
#include <stdio.h>
#include <stdint.h>

void ok(const char *name, FILE *fp) {
    size_t n = strlen(name);
    long off = ftell(fp);
    off_t end = ftello(fp);
    uint32_t wide = strlen(name);
    int width = (int)strlen(name);
    printf("%.*s\n", (int)strlen(name), name);
    unsigned short port = htons(8080);
    short flags = 0;
    uint8_t version = 2;
    char c = name[0];
    int len = strlen(name);
}
