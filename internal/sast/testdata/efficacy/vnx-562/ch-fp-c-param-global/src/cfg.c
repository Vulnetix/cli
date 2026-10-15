struct config { int level; char name[16]; };
static struct config g_config;

struct config *get_config(void)
{
    return &g_config;
}

int *slot(int *arr, int i)
{
    return &arr[i];
}

char *name_of(struct config *self)
{
    return self->name;
}

int *level_of(struct config *self)
{
    return &self->level;
}
