#include <cstdlib>
#include <memory>
#include <vector>

void fine(std::size_t n)
{
    char *raw = static_cast<char *>(std::malloc(n));
    std::free(raw);

    int *arr = new int[n];
    delete[] arr;

    auto *one = new std::vector<int>();
    delete one;

    std::unique_ptr<int[]> owned(new int[n]);
    std::shared_ptr<int> sp = std::make_shared<int>(4);
    auto arr2 = std::make_unique<char[]>(n);
}
