#define MAX_USERS 64
#include <string.h>

static int users[MAX_USERS];
char line[128];

void finish(void)
{
~>    users[MAX_USERS] = -1;
~>    line[128] = '\0';
}
