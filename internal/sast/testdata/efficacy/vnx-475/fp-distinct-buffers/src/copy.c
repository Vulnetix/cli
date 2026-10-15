#include <stdio.h>
#include <string.h>

struct pair { char a[16]; char b[16]; };

void copies(char *dst, const char *src, char *buf, size_t n, struct pair *p, const char *name)
{
    memmove(buf, buf + 1, n - 1);
    memcpy(dst, src, n);
    strcpy(dst, src);
    strncpy(dst, dst_backup, n);
    memcpy(p->a, p->b, sizeof p->a);
    sprintf(buf, "%s", name);
    snprintf(buf, sizeof(buf), "%d:%s", (int)strlen(buf), name);
    fflush(stdout);
    fflush(stdin_copy);
    printf("%s\n", name ? name : "(null)");
    memset(buf, 0, n);
    if (dst == NULL)
        return;
}
