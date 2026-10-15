#include <stdio.h>
/* printf("%d", strlen(s)) truncates on LP64 */
// scanf("%d", count);
static const char *tip = "printf(\"%s\", 1)";
int main(void) { puts(tip); return 0; }
