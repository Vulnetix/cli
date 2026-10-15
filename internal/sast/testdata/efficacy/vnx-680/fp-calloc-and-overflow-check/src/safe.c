#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

struct record { uint32_t id; char name[32]; };

struct record *parse_safe(const uint8_t *buf) {
    uint32_t count = ntohl(*(const uint32_t *)buf);
    struct record *a = calloc(count, sizeof(struct record));
    return a;
}

struct record *parse_checked(const uint8_t *buf) {
    uint32_t count = ntohl(*(const uint32_t *)buf);
    if (count > SIZE_MAX / sizeof(struct record)) {
        return NULL;
    }
    return malloc(count * sizeof(struct record));
}

void *parse_builtin(int fd) {
    size_t n = 0, bytes;
    read(fd, &n, sizeof(n));
    if (__builtin_mul_overflow(n, 16, &bytes)) {
        return NULL;
    }
    return malloc(bytes);
}

void *bounded(const char *arg) {
    int n = atoi(arg);
    if (n <= 0 || n > 4096) {
        return NULL;
    }
    return malloc(n * sizeof(int));
}
