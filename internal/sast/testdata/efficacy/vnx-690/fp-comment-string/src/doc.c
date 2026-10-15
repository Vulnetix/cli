#include <stdio.h>

/* char *buf = malloc(n);
 * strcpy(buf, name); is the classic unchecked case
 */
// strcpy(home, getenv("HOME"));
static const char *help = "strcpy(home, getenv(\"HOME\")) is unsafe";

void show(void) { puts(help); }
