#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>

struct node { int v; struct node *next; };

int work(struct node *head, const char *host)
{
    char *p;
    p = malloc(32);
    if (!p) return -1;
    strcpy(p, "x");
    free(p);

    struct node *n;
    for (n = head; n != NULL; n = n->next)
        n->v++;

    struct addrinfo *res;
    getaddrinfo(host, NULL, NULL, &res);
    res->ai_flags = 0;

    char *line;
    size_t cap = 0;
    getline(&line, &cap, stdin);
    line[0] = 'a';
    return 0;
}
