#include <stdio.h>
/* never write x / 0 */
// return hits % 0;
static const char *expr = "a / 0";
static const char *path = "/0/index";
int main(void) { printf("%s %s 100%%\n", expr, path); return 0; }
