#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>

int parse_addr(const char *text, struct in_addr *out) {
    return inet_pton(AF_INET, text, out);
}

long decimal(const char *s) {
    return strtol(s, NULL, 10);
}

int count(const char *buf) {
    int n;
    sscanf(buf, "%d", &n);
    return n;
}

unsigned long loopback(void) {
    return inet_addr("127.0.0.1");
}
