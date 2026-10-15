#include <netdb.h>
#include <thread>
#include <vector>

void resolve(const char *host) {
~>    struct hostent *h = ::gethostbyname(host);
    (void)h;
}

void run(const std::vector<const char *> &hosts) {
    std::vector<std::thread> ts;
    for (auto h : hosts) ts.emplace_back(resolve, h);
    for (auto &t : ts) t.join();
}
