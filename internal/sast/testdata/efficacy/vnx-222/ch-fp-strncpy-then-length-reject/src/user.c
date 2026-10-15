#include <string.h>

int is_admin(const char *login)
{
    char name[16];
    if (strlen(login) >= sizeof(name))
        return 0;
    strncpy(name, login, sizeof(name));
    return strcmp(name, "admin") == 0;
}
