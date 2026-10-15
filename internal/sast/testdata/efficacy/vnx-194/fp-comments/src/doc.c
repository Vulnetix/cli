#include <ctype.h>
/* isspace(*p) is undefined for negative char values: cast first. */
// tolower(c) needs (unsigned char)c
static const char *msg = "use isdigit((unsigned char)c)";

int ok(int c) { return isdigit(c); }
