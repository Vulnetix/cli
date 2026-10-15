#include <inttypes.h>
#include <stdio.h>

#define LOG(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__)

void w(uint64_t v, const char *name) {
    log_printf("%s %s\n", name);
    ctx->printf("%d\n");
    printf("%" PRIu64 "\n", v);
    printf("%1$s %1$s\n", name);
    printf("%s %d\n",
           name, 3);
    // printf("%s %s\n", name); is wrong
}
