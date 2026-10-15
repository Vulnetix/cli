#include <stdio.h>
#include <string.h>

void show(const char *name, char *buf, size_t n) {
~>    printf("name is %d bytes\n", strlen(name));
~>    fprintf(stderr, "header %u, total %lu\n", sizeof(struct header), n);
~>    snprintf(buf, n, "%s=%x", name, sizeof buf);
}
