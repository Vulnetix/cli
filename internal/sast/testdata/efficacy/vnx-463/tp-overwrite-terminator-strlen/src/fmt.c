#include <string.h>

void add_suffix(char *name, char c)
{
~>    name[strlen(name)] = c;
}
