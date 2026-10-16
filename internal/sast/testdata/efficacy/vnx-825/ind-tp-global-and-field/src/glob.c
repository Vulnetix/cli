struct config { int level; };
struct conn { char *label; };

static struct config *active;

void activate(int level)
{
    struct config cfg;
    cfg.level = level;
~>    active = &cfg;
}

void name_conn(struct conn *c)
{
    char buf[32] = "tmp";
~>    c->label = buf;
}
