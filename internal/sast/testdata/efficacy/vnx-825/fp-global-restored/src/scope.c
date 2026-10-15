struct config { int verbose; };

struct config *active;

void apply(void);

void with_config(int verbose)
{
    struct config cfg;
    cfg.verbose = verbose;
    active = &cfg;
    apply();
    active = NULL;
}

void set_local(void)
{
    struct config *active;
    struct config mine;
    active = &mine;
    (void)active;
}
