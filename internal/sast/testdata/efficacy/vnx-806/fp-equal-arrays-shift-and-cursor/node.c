#include <string.h>

#define IP_LEN 46

struct node { char ip[IP_LEN]; };

void set_ip(struct node *n, char *rule, size_t total) {
    char ip[IP_LEN];
    char copy[IP_LEN];
    resolve(ip, sizeof(ip));
    memcpy(n->ip, ip, sizeof(ip));
    memcpy(copy, ip, sizeof(ip));
    char *end = strchr(rule, ' ');
    memmove(rule, end, strlen(end) + 1);
    char *out = malloc(total);
    char *sp = out;
    for (int i = 0; i < 3; i++) {
        size_t slen = strlen(parts[i]);
        memcpy(sp, parts[i], slen);
        sp += slen;
    }
}
