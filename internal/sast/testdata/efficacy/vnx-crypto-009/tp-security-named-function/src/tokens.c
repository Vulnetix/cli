#include <stdlib.h>

static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static unsigned long
generate_api_token(void)
{
~>    return ((unsigned long) random() << 31) ^ (unsigned long) random();
}

void make_password(char *buf, size_t len)
{
    size_t i;
    for (i = 0; i + 1 < len; i++)
~>        buf[i] = charset[rand() % 62];
    buf[i] = '\0';
}

int new_otp(void) {
    int out;
~>    out = 100000 + rand() % 900000;
    return out;
}
