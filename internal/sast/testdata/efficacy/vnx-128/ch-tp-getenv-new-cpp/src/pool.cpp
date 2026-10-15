#include <cstdlib>

struct Item { char data[64]; };

Item *make_pool()
{
    int workers = std::atoi(std::getenv("WORKERS"));
~>    Item *pool = new Item[workers * 4];
    return pool;
}
