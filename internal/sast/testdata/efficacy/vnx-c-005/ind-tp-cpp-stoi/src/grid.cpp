#include <cstdlib>
#include <string>

struct Cell { int value; int flags; };

Cell *make_grid(const std::string &rows_arg, const std::string &cols_arg)
{
    int rows = std::stoi(rows_arg);
    int cols = std::stoi(cols_arg);
~>    Cell *grid = static_cast<Cell *>(std::malloc(rows * cols * sizeof(Cell)));
    return grid;
}
