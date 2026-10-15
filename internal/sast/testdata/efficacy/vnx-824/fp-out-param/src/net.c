#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>

int family(const char *host)
{
    struct addrinfo hints = {0};
    struct addrinfo *res;
    if (getaddrinfo(host, NULL, &hints, &res) != 0)
        return -1;
    int f = res->ai_family;
    freeaddrinfo(res);
    return f;
}

void line_of(FILE *in)
{
    char *line;
    size_t cap = 0;
    getline(&line, &cap, in);
    free(line);
}
