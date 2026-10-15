#include <stdio.h>

/* char *p = malloc(n);
 * memcpy(p, src, n);  -- always check the result first
 */
// char *home = getenv("HOME"); strcpy(dst, home);
static const char *doc = "p = malloc(n); p->x = 1;";

int main(void)
{
    puts(doc);
    return 0;
}
