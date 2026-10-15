#include <stdio.h>

void rotate(struct logger *lg)
{
    fclose(lg->fp);
    reopen(&lg->fp);
    fclose(lg->fp);
    lg->fp = fopen(lg->path, "a");
}

/* fclose(fp); fclose(fp); is a double close */
