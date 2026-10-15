#include <random>
#include <string>

static const char kAlphabet[] = "@@sample:a[b]cd[e]fg[h]ij[k]lm[n]op[q]rs[t]uv[w]xy[z]01[2]34[5]67[8]9@@";

std::string NewSessionId() {
    std::mt19937_64 engine(std::random_device{}());
    std::uniform_int_distribution<int> pick(0, sizeof(kAlphabet) - 2);
    std::string id;
    for (int i = 0; i < 32; ++i) {
~>        id.push_back(kAlphabet[pick(engine)]);
    }
    return id;
}
