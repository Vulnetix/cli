#include <stdio.h>
#include <string.h>

void copy_user(char *dst, size_t dstlen, const char *user)
{
    strlcpy(dst, user, dstlen);
}

void build_greeting(char *out, size_t outlen, const char *user)
{
    snprintf(out, outlen, "hello %s", user);
}

int read_name(char name[64])
{
    if (scanf("%63s", name) != 1)
        return -1;
    return 0;
}

int read_line(char *buf, size_t n)
{
    if (fgets(buf, (int)n, stdin) == NULL)
        return -1;
    buf[strcspn(buf, "\n")] = '\0';
    return 0;
}

void copy_bounded(char *dst, size_t n, const char *src)
{
    strncpy(dst, src, n - 1);
    dst[n - 1] = '\0';
}

void secure_copy(char *dst, rsize_t n, const char *src)
{
    strcpy_s(dst, n, src);
    strcat_s(dst, n, src);
}

void label(char *out, const char *name)
{
    sprintf(out, "name=%.32s id=%d", name, 7);
}
