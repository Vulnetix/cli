#include "compat.h"

/*
   History: this used to call strcpy(buf, name) and gets(line)
   before the copy helpers existed.
*/

void report(const char *name, struct lexer *lx, char *dst)
{
    log_warn("strcpy(dst, src) is banned; use safe_strlcpy(dst, src, n)");
    log_warn("gets(buf) was removed in C11");
    safe_strlcpy(dst, name, 32); // was: strcpy(dst, name);
    my_strcat(dst, name);
    redis_strlcpy(dst, name, 32);
    lx->gets(lx);
    lx.strcpy(dst, name);
    fgets(dst, 32, stdin); /* not gets(dst) */
}
