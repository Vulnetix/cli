#include <random>
#include <string>

static const char kAlphabet[] = "@@sample:a[b]cd[e]fg[h]ij[k]lm[n]op[q]rs[t]uv[w]xy[z]01[2]34[5]67[8]9@@";

std::string generate_password(size_t n) {
~>    std::mt19937_64 gen(12345);
    std::uniform_int_distribution<size_t> pick(0, sizeof(kAlphabet) - 2);
    std::string password;
    for (size_t i = 0; i < n; ++i) password += kAlphabet[pick(gen)];
    return password;
}
