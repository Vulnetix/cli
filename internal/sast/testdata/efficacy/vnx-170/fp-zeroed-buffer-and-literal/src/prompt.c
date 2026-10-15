#include <string.h>

static char g_label[64];

struct cfg { char prompt[32]; char path[108]; };

void set_prompt(struct cfg *c)
{
    strncpy(c->prompt, "debugger> ", sizeof(c->prompt));
}

void set_path(struct cfg *c, const char *path)
{
    memset(c, 0, sizeof(*c));
    strncpy(c->path, path, sizeof(c->path) - 1);
}

void set_label(const char *label)
{
    strncpy(g_label, label, sizeof(g_label) - 1);
}

void set_local(const char *src)
{
    char local[40] = {0};
    strncpy(local, src, sizeof(local) - 1);
    use(local);
}
