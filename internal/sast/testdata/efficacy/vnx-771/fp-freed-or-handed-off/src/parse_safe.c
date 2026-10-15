#include <stdlib.h>
#include <string.h>

char *pick(const char *a, const char *b) {
    char *s = strdup(a);
    if (strlen(b) > strlen(a)) {
        free(s);
        s = strdup(b);
    }
    return s;
}

void keep(struct list *l, size_t n) {
    char *node = malloc(n);
    list_add(l, node);
    node = malloc(n);
    list_add(l, node);
}

void loop(size_t n) {
    for (int i = 0; i < 3; i++) {
        char *p = malloc(n);
        use(p);
        free(p);
    }
}

void other(size_t n) {
    char *p = malloc(n);
    free(p);
}

void again(size_t n) {
    char *p = malloc(n);
    consume(p);
}

void branches(int big, size_t n) {
    char *p;
    if (big) {
        p = malloc(n * 4);
    } else {
        p = malloc(n);
    }
    free(p);
}

void retry(size_t n) {
    char *p = malloc(n);
    if (p == NULL) {
        p = malloc(n / 2);
    }
    free(p);
}
