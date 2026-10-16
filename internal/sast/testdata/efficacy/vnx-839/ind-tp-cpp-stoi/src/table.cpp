#include <string>
#include <array>

std::array<int, 8> slots;

void put(const std::string& s, int v) {
    int slot = std::stoi(s);
~>    if (slot > 7) {
        return;
    }
    slots[slot] = v;
}
