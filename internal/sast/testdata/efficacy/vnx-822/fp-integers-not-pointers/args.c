#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    unsigned long n = strtoul(argv[1], NULL, 10);
    char *buf = malloc(n);
    int port = atoi(argv[2]);
    int count;
    sscanf(argv[3], "%d", &count);
    printf("%p %d\n", (void *)buf, port);
    /* (char *)strtoul(argv[1], NULL, 16) would be the bug */
    free(buf);
    return count;
}
