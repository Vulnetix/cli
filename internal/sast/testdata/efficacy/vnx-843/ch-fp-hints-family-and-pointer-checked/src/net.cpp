#include <memory>
#include <netdb.h>
#include <netinet/in.h>
#include <cstring>

struct Event {
    virtual ~Event() = default;
};

struct KeyEvent : public Event {
    int keycode = 0;
};

int key_of(const std::shared_ptr<Event> &ev)
{
    if (auto k = std::dynamic_pointer_cast<KeyEvent>(ev))
        return k->keycode;
    return -1;
}

unsigned short v6_port(const char *host)
{
    struct addrinfo hints, *res;
    std::memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET6;
    if (getaddrinfo(host, "443", &hints, &res) != 0)
        return 0;
    auto *s6 = reinterpret_cast<struct sockaddr_in6 *>(res->ai_addr);
    unsigned short p = ntohs(s6->sin6_port);
    freeaddrinfo(res);
    return p;
}
