void defaults(struct cfg *c)
{
    strcpy(c->name, "default");
    strcat(c->name, DEFAULT_SUFFIX);
    strcpy(c->mode, c->enabled ? "on" : "off");
}
