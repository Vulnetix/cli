#include <stdio.h>
#include <time.h>

static char session_token[32];

void issue(void)
{
~>    snprintf(session_token, sizeof session_token, "%ld", (long) time(NULL));
}
