#include <random>
#include <vector>

struct Tile { int kind; };

std::vector<Tile> generate_level(int width, int height)
{
    std::mt19937 gen(12345);
    std::uniform_int_distribution<int> dist(0, 3);
    std::vector<Tile> tiles(width * height);
    for (auto &t : tiles) {
        t.kind = dist(gen);
    }
    return tiles;
}
