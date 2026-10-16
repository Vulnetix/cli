#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    FILE *f = fopen("/var/lib/helper/counter", "r+");
    if (setuid(getuid()) != 0) {
        perror("setuid");
        return 1;
    }
    if (f == NULL)
        return 1;
    bump_counter(f);
    fclose(f);
    return 0;
}
