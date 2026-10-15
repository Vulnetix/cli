#include <stdio.h>
#include <stdlib.h>

int open_both(const char *a, const char *b)
{
    char *name = malloc(64);
    FILE *fa = fopen(a, "r");
    if (!fa) {
        free(name);
        goto fail;
    }
    FILE *fb = fopen(b, "r");
    if (!fb) {
        fclose(fa);
        goto fail_name;
    }
    fclose(fb);
    fclose(fa);
    free(name);
    return 0;
fail_name:
    free(name);
fail:
    return -1;
}
