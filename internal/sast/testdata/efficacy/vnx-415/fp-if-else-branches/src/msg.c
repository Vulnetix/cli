#include <stdlib.h>

int finish(struct msg *m, int ok)
{
    if (ok) {
        free(m->body);
    } else {
        log_drop(m);
        free(m->body);
    }
    switch (m->kind) {
    case 1:
        free(m->extra);
        break;
    case 2:
        free(m->extra);
        break;
    }
    if (m->flags) free(m->hdr);
    else free(m->hdr);
    return 0;
}

int early(char *p)
{
    if (p[0] == 0) {
        free(p);
        return -1;
    }
    free(p);
    return 0;
}
