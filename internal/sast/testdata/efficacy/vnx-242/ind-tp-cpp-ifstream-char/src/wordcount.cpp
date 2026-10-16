#include <fstream>
#include <map>
#include <string>

std::map<std::string, int> count_words(const char *path) {
    std::ifstream in(path);
    std::map<std::string, int> counts;
    char word[16];
~>    while (in >> word) {
        counts[word]++;
    }
    return counts;
}
