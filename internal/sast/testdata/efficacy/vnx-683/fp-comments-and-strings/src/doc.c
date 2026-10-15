#include <stdio.h>
/* memcpy(src, dst, n) is the classic mistake */
// memset(buf, n, 0);
static const char *bad = "fputs(stderr, msg)";
int main(void) { puts(bad); return 0; }
