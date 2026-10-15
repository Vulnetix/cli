#include <cstdlib>
#include <new>

struct Node {
    int v;
};

void slab()
{
    void *mem = std::malloc(sizeof(Node));
    Node *n = new (mem) Node{3};
    n->~Node();
    std::free(mem);
}

void allocator_api(Allocator &alloc)
{
    char *p = new char[16];
    alloc.free(p);
    pool->delete_later(p);
    delete[] p;
}
