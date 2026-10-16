#include <stdio.h>
#include <stddef.h>

#define RETRIES 5

void run(const char *names[], size_t count)
{
    for (int i = 0; i < RETRIES; i++) {
        puts("retry");
    }
    for (size_t j = 0; j < count; j++) {
        puts(names[j]);
    }
}
