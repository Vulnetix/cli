#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

int handle(const unsigned char *pkt, char **argv) {
    char payload[512];
    char buf[128];
    uint16_t len = ntohs(*(const uint16_t *)pkt);
    if (len > sizeof(payload))
        return -1;
    memcpy(payload, pkt + 2, len);
    int n = atoi(argv[2]);
    n = n < (int)sizeof(buf) ? n : (int)sizeof(buf);
    memset(buf, 'A', n);
    size_t k = strtoul(argv[3], NULL, 10);
    memcpy(buf, pkt, MIN(k, sizeof(buf)));
    return 0;
}
