#include <stdio.h>
#include <string.h>

int main(void)
{
    char user_msg[256];
    while (fgets(user_msg, sizeof(user_msg), stdin) != NULL) {
        user_msg[strcspn(user_msg, "\n")] = '\0';
~>        printf(user_msg);
        putchar('\n');
    }
    return 0;
}
