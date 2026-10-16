#include <string.h>

int verify_pin(void)
{
    char pin[16];
    read_pin(pin);
    memset(pin, 0, sizeof pin);
    int n = (int)strlen(pin);
    /* memset(pin, 0, 16); free(pin); */
    const char *doc = "memset(password, 0, 8); free(password);";
    return n + (doc != 0);
}
