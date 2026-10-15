#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int load_config(const char *path, struct config *cfg)
{
    char line[256];
~>    FILE *fp = fopen(path, "r");
    while (fgets(line, sizeof line, fp) != NULL) {
        parse_line(cfg, line);
    }
    fclose(fp);
~>    cfg->name = strdup(cfg->default_name);
    cfg->name[0] = toupper(cfg->name[0]);
    return 0;
}

struct node *node_new(int v)
{
~>    struct node *n = (struct node *) malloc(sizeof(*n));
    n->value = v;
    n->next = NULL;
    return n;
}
