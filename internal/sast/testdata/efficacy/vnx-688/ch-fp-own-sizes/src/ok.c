#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

void ok(FILE *fp, const char *in)
{
    char dst[64];
    char src[32];
    char buf[128];
    struct stat st;
    memcpy(dst, src, sizeof(src));
    snprintf(buf, sizeof buf, "%s", in);
    strlcpy(dst, in, sizeof(dst));
    memset(&st, 0, sizeof(struct stat));
    fgets(buf, sizeof(buf), fp);
}
