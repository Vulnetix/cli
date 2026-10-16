#include <stdio.h>
int copy(const char *p)
{
    FILE *fp = fopen(p, "r");
    consume(fp);
    fclose(fp);
    cleanup_state();
~>    fclose(fp);
    return 0;
}
