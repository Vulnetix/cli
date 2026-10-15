#include <memory>

void Table::rebuild() {
    delete root_;
    root_ = new Node();
    populate(root_);
    delete root_;
    root_ = nullptr;
}

void Table::swap_out(Node *n) {
    delete n;
    n = take_spare();
    delete n;
}

void clear_name(struct rec *r) {
    free(r->name);
    if ((r->name = strdup("")) == NULL)
        abort();
    free(r->name);
}
