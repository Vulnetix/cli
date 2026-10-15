void Pool::grow(size_t n) {
    int *slots = new int[n];
    init(slots, n);
~>    delete slots;
}

void Pool::one() {
    Node *node = new Node;
    attach(node);
~>    delete [] node;
}
