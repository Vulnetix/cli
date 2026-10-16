#include <stdio.h>

/* buf = realloc(buf, cap); is the classic leak */
// p = malloc(1); p = malloc(2);
const char *tip = "buf = realloc(buf, cap);";

int main(void) { puts(tip); return 0; }
