#include <string.h>
#include <sys/socket.h>

#define NAME_LEN 32
#define MAX_INPUT 256

int get_user(int sock, const char *fallback) {
    char user[NAME_LEN];
~>    if (recv(sock, user, MAX_INPUT, 0) <= 0) {
~>        strncpy(user, fallback, MAX_INPUT);
    }
~>    snprintf(user, 64, "%s", fallback);
    return 0;
}
