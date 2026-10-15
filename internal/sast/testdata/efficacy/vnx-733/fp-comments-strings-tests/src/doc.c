#include <stdio.h>
/* memset(password, 0, n); free(password); is a dead store */
// if (p + n < p) is undefined
void say(void) { puts("memset(password, 0, 8);"); }
