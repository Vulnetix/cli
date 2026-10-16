#include <stdio.h>
#include <sodium.h>
#include "engine.h"

void report_status(struct engine *e)
{
    if (sodium_init() >= 0) {
        printf("crypto ready\n");
    }
    if (!isInitialized(e)) {
        fprintf(stderr, "engine not initialised yet\n");
    }
}
