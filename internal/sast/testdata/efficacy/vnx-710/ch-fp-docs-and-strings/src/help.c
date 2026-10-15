#include <stdio.h>
/* Never write #pragma warning(disable: 4996) in this tree. */
// #pragma GCC diagnostic ignored "-Wformat-security"
static const char *hint = "#pragma warning(disable: 4996) is banned";
void show(void) { puts(hint); }
