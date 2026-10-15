#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int load_config(const char *path)
{
    struct config *cfg = calloc(1, sizeof(*cfg));
    if (cfg == NULL)
        return -ENOMEM;
    FILE *fp = fopen(path, "r");
    if (!fp)
~>        return -errno;
    parse_lines(fp, cfg);
    fclose(fp);
    register_config(cfg);
    return 0;
}
