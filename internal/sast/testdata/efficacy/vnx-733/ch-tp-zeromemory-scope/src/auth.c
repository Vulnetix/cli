#include <windows.h>

BOOL check_login(const char *user) {
    char password[128];
    BOOL ok;
    read_password(password, sizeof(password));
    ok = verify(user, password);
~>    ZeroMemory(password, sizeof(password));
    return ok;
}
