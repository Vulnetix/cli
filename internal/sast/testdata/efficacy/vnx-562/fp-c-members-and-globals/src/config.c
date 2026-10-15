struct config { int port; char host[64]; };

static struct config global_cfg;
static char scratch[256];

struct config *get_config(void)
{
    return &global_cfg;
}

char *get_scratch(void)
{
    return scratch;
}

int *port_of(struct config *c)
{
    return &c->port;
}

char *host_of(struct config *c)
{
    return c->host;
}
