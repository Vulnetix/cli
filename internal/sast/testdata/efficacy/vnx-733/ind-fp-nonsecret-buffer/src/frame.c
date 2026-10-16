#include <stdlib.h>
#include <string.h>

void frame_release(unsigned char *frame, size_t n)
{
    memset(frame, 0, n);
    free(frame);
}

void mask_secret(char *secret, size_t n)
{
    char masked[64];
    memset(masked, '*', sizeof(masked));
    memset(secret, 0xff, n);
    free(secret);
}
