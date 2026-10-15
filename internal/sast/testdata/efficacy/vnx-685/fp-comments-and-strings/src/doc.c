#include <stdio.h>
/* printf("%s %d\n", user); is wrong */
// scanf("%d %d", &a);
static const char *tip = "open(path, O_CREAT) needs a mode";
int main(void) { puts(tip); return 0; }
