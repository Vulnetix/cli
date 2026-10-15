#include <string>
#include <vector>

constexpr size_t kMaxRows = 10000;

void Options::parse(const std::string &v)
{
    size_t rows = std::stoul(v);
    if (rows > kMaxRows) {
        throw std::out_of_range("rows");
    }
    table_.reserve(rows);
    auto *cells = new Cell[rows];
    use(cells);
}
