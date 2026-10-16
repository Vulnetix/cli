#include <stdio.h>
#include <string.h>

int check_password(const char *user, int (*verify)(const char *, const char *))
{
    char password[128];
    int ok;

    if (fgets(password, sizeof(password), stdin) == NULL)
        return -1;
    password[strcspn(password, "\n")] = '\0';
    ok = verify(user, password);
~>    memset(password, 0, sizeof(password));
    return ok;
}
