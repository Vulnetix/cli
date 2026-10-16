#include <random>
#include <string>
#include <chrono>
#include "SessionManager.h"

namespace web {

static const char kAlphabet[] = "0123456789abcdef";

std::string SessionManager::generateSessionId()
{
    std::mt19937 engine(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));
    std::uniform_int_distribution<int> dist(0, 15);
    std::string id;
    id.reserve(32);
    for (int i = 0; i < 32; ++i) {
~>        id.push_back(kAlphabet[dist(engine)]);
    }
    return id;
}

}  // namespace web
