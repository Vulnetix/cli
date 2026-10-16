#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct config {
    char *listen_addr;
    int port;
};

static int parse_port(const char *s, int *out)
{
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (*end != '\0' || v <= 0 || v > 65535)
        return -1;
    *out = (int)v;
    return 0;
}

int config_load_line(struct config *cfg, const char *line)
{
    char *copy = strdup(line);
    if (copy == NULL)
        return -ENOMEM;

    char *eq = strchr(copy, '=');
    if (eq == NULL) {
        fprintf(stderr, "config: missing '=' in %s\n", line);
~>        return -EINVAL;
    }
    *eq = '\0';

    if (strcmp(copy, "port") == 0) {
        int rc = parse_port(eq + 1, &cfg->port);
        free(copy);
        return rc;
    }

    free(copy);
    return 0;
}
