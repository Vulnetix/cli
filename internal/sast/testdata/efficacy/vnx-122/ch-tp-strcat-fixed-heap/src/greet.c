#include <stdlib.h>
#include <string.h>

char *greeting(const char *user)
{
    char *msg = (char *) calloc(32, 1);
    strcpy(msg, "Hello, ");
~>    strcat(msg, user);
    return msg;
}
