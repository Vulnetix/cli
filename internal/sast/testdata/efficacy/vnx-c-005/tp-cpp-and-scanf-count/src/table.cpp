#include <cstdio>
#include <cstdlib>

struct Cell { int a; int b; };

Cell *load_table()
{
    size_t n;
    std::scanf("%zu", &n);
~>    Cell *cells = static_cast<Cell *>(std::malloc(n * sizeof(Cell)));
    return cells;
}

int *load_ints(const char *line)
{
    int count = 0;
    sscanf(line, "%d", &count);
~>    return (int *)malloc(count*sizeof(int));
}
