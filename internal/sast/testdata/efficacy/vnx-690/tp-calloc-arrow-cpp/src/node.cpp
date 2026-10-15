#include <cstdlib>

struct node { int key; node *next; };

node *make_node(int key) {
    node *n = (node *) calloc(1, sizeof(node));

~>    n->key = key;
    return n;
}

void open_log(const char *path) {
    FILE *fp = fopen(path, "a");
    // write the banner
~>    fprintf(fp, "started\n");
}
