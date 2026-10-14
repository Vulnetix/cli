#include <stdio.h>

int main(void)
{
    char user_msg[256];

    if (fgets(user_msg, sizeof(user_msg), stdin) == NULL)
        return 1;
~>    printf(user_msg);
    return 0;
}
