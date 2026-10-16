#include <stdlib.h>
#include <string.h>

void load_home(char *home)
{
~>    strcpy(home, getenv("HOME"));
}
