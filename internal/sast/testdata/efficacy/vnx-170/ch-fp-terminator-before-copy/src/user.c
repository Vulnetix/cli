#include <string.h>

void set_user(const char *src)
{
    char user[32];
    user[sizeof(user) - 1] = '\0';
    strncpy(user, src, sizeof(user) - 1);
    store_user(user);
}

void set_label(char *dst, const char *src, size_t n)
{
    strncpy(dst, src, n);
    dst[n - 1] = 0;
}
